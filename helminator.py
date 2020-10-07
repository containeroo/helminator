import logging
import logging.handlers
import os
import sys
import re

from collections import namedtuple
from pathlib import Path

__version__ = "1.7.1"

ansible_chart_repos, ansible_helm_charts, chart_updates = [], [], []
errors = False
pattern = re.compile(r"^{{.*\.(\w+)  ?}}")
helm_task_names = ['community.kubernetes.helm', 'helm']
helm_repository_task_names = ['community.kubernetes.helm_repository', 'helm_repository']

try:
    import requests
    import semver
    import yaml
    from slack import WebClient
    from slack.errors import SlackApiError
except Exception:
    sys.stderr.write("requirements are not satisfied! see 'requirements.txt'\n")
    sys.exit(1)


def check_env_vars():
    search_dir = os.environ.get("HELMINATOR_ROOT_DIR")
    slack_token = os.environ.get("HELMINATOR_SLACK_API_TOKEN")
    slack_channel = os.environ.get("HELMINATOR_SLACK_CHANNEL")
    enable_prereleases = os.environ.get("HELMINATOR_ENABLE_PRERELEASES", "false").lower() == "true"

    loglevel = os.environ.get("HELMINATOR_LOGLEVEL", "info").lower()

    vars_file = os.environ.get("HELMINATOR_VARS_FILE")

    if not search_dir:
        raise EnvironmentError(
            "environment variable 'HELMINATOR_ROOT_DIR' not set!")

    if not slack_token:
        raise EnvironmentError(
            "environment variable 'HELMINATOR_SLACK_API_TOKEN' not set!")

    if not slack_channel:
        raise EnvironmentError(
            "environment variable 'HELMINATOR_SLACK_CHANNEL' not set!")

    Env_vars = namedtuple('Env_vars', ['search_dir',
                                       'slack_token',
                                       'slack_channel',
                                       'loglevel',
                                       'enable_prereleases',
                                       'vars_file',
                                       ]
                          )
    return Env_vars(search_dir, slack_token, slack_channel, loglevel, enable_prereleases, vars_file)


def setup_logger(loglevel='info'):
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if loglevel == "critical":
        loglevel = logging.CRITICAL
    elif loglevel == "error":
        loglevel = logging.ERROR
    elif loglevel == "warning":
        loglevel = logging.WARNING
    elif loglevel == "info":
        loglevel = logging.INFO
    elif loglevel == "debug":
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO

    default_format = logging.Formatter("%(asctime)s [%(levelname)-7.7s] %(message)s")
    debug_format = logging.Formatter("%(asctime)s [%(filename)s:%(lineno)s - %(funcName)-20s ] %(message)s")

    console_logger = logging.StreamHandler(sys.stdout)
    console_logger.setLevel(loglevel)
    console_logger.setFormatter(debug_format if loglevel == logging.DEBUG else default_format)
    root_logger.addHandler(console_logger)


def process_yaml(search_dir, additional_vars=None, enable_prereleases=False):
    """iterate over directory and extract Helm chart name and version

    Keyword Arguments:
        search_dir {str} -- path to directory
        additional_vars {list} -- list with dicts with additional vars
        enable_prereleases {bool} -- process pre-releases (default: False)
    """
    search_dir = Path(search_dir)
    if not search_dir.is_dir():
        raise NotADirectoryError(f"'{search_dir}' is not a directory")

    for item in search_dir.glob("**/*"):
        if not item.is_file():
            continue
        if item.suffix not in ['.yml', '.yaml']:
            continue
        if 'collections/' in str(item.absolute()):
            continue
        try:
            get_ansible_helm(path=item.absolute(),
                             additional_vars=additional_vars,
                             enable_prereleases=enable_prereleases)
        except Exception as e:
            logging.error("unexpected exception while parsing yaml "
                          f"'{item.absolute}'. {str(e)}")


def get_ansible_helm(path, additional_vars=None, enable_prereleases=False):
    """load ansible yamls and search for Helm chart name and version

    Keyword Arguments:
        path {str} -- path to yaml
        vars {list} -- list with dicts with extra vars
        enable_prereleases {bool} -- process pre-releases (default: False)
    """

    def _parse_ansible_helm_task(item):
        for task_name in helm_task_names:
            if item.get(task_name):
                _extract_ansible_helm_task(chart_ref=item[task_name]['chart_ref'],
                                           chart_version=item[task_name]['chart_version'] if
                                           item[task_name].get('chart_version') else None)

    def _parse_ansible_helm_repository_task(item):
        for task_name in helm_repository_task_names:
            if item.get(task_name):
                with_items = item.get('with_items')

                if additional_vars and isinstance(with_items , str):
                    search = re.sub(r'[^\w]', '', with_items)
                    with_items = additional_vars.get(search)

                if not isinstance(with_items, list):
                    with_items = None

                _extract_ansible_helm_repository_task(
                    repo_name=item[task_name]['name'],
                    repo_url=item[task_name]['repo_url'],
                    with_items=with_items)

    def _extract_ansible_helm_task(chart_ref, chart_version):
        if not any(chart for chart in ansible_helm_charts if chart == chart_ref):
            segments = chart_ref.split('/')
            if len(segments) > 2:
                return
            repo_name = segments[0]
            chart_name = segments[-1]
            if not chart_version or not semver.VersionInfo.isvalid(chart_version.lstrip('v')):
                logging.warning(f"ansible helm task '{repo_name}/{chart_name}' has"
                                f" an invalid version '{chart_version}'")
                return
            version = semver.VersionInfo.parse(chart_version.lstrip('v'))
            if version.prerelease and not enable_prereleases:
                logging.warning(f"skipping ansible helm task '{repo_name}/{chart_name}' with version '{chart_version}'"
                                "because it is a pre-release")
                return
            chart = {
                'name': chart_name,
                'version': chart_version,
                'repo': repo_name
            }
            logging.debug(f"found ansible helm task '{repo_name}/{chart_name}' with version '{chart_version}'")
            ansible_helm_charts.append(chart)

    def _extract_ansible_helm_repository_task(repo_name, repo_url, with_items):
        if not any(repo for repo in ansible_chart_repos if repo['name'] == repo_name):
            if with_items:
                item_repo_name = re.findall(pattern, repo_name)
                if not item_repo_name:
                    logging.warning(f"could not find ansible helm_repository name in '{repo_name}'")
                    return
                item_repo_name = item_repo_name[0]

                item_repo_url = re.findall(pattern, repo_url)
                if not item_repo_url:
                    logging.warning(f"could not find ansible helm_repository url in '{repo_url}'")
                    return
                item_repo_url = item_repo_url[0]

                for _item in with_items:
                    repo = {
                        'name': _item[item_repo_name],
                        'url': _item[item_repo_url].rstrip('/')
                    }
                    logging.debug(
                        f"found ansible helm_repository task '{_item[item_repo_name]}' with "
                        f"url '{_item[item_repo_url]}'")
                    ansible_chart_repos.append(repo)
                return
            repo = {
                'name': repo_name,
                'url': repo_url.rstrip('/')
            }
            logging.debug(f"found ansible helm_repository task '{repo_name}' with url '{repo_url}'")
            ansible_chart_repos.append(repo)

    def _extract_tasks(key: str, item: dict):
        for sub_item in item[key]:
            if not isinstance(sub_item, dict):
                continue
            if sub_item.get('block'):
                _extract_tasks(key='block', item=sub_item)
            if sub_item.get('community.kubernetes.helm') or sub_item.get('helm'):
                _parse_ansible_helm_task(item=sub_item)
            if sub_item.get('community.kubernetes.helm_repository') or sub_item.get('helm_repository'):
                _parse_ansible_helm_repository_task(item=sub_item)

    try:
        with open(path) as stream:
            tasks = yaml.safe_load(stream)
    except Exception:
        # ignore unparsable yaml files, since ansible already does this
        return

    for task in tasks:
        if not isinstance(task, dict):
            continue
        if task.get('pre_tasks'):
            _extract_tasks(key='pre_tasks', item=task)
        if task.get('tasks'):
            _extract_tasks(key='tasks', item=task)
        if task.get('block'):
            _extract_tasks(key='block', item=task)
        if task.get('community.kubernetes.helm') or task.get('helm'):
            _parse_ansible_helm_task(item=task)
        if task.get('community.kubernetes.helm_repository') or task.get('helm_repository'):
            _parse_ansible_helm_repository_task(item=task)


def get_chart_updates(enable_prereleases=False):
    """get Helm chart yaml from repo and compare chart name and version with ansible
    chart name and version

    Keyword Arguments:
         enable_prereleases {bool} -- process pre-releases (default: False)
    """
    global errors
    for ansible_chart_repo in ansible_chart_repos:
        ansible_helm_charts_matching = [chart for chart in ansible_helm_charts if
                                        chart['repo'] == ansible_chart_repo['name']]

        if not ansible_helm_charts_matching:
            logging.debug(f"skipping helm repository '{ansible_chart_repo['url']}' since no ansible "
                          "helm task uses it")
            continue

        logging.debug(f"processing helm repository '{ansible_chart_repo['url']}'")
        try:
            helm_chart_url = f"{ansible_chart_repo['url']}/index.yaml"
            repo_response = requests.get(url=helm_chart_url)
        except Exception as e:
            logging.error(f"unable to fetch helm repository '{helm_chart_url}'. {str(e)}")
            errors = True
            continue

        if repo_response.status_code != 200:
            logging.error(f"'{helm_chart_url}' returned: {repo_response.status_code}")
            errors = True
            continue

        try:
            repo_charts = yaml.safe_load(repo_response.content)
        except Exception as e:
            logging.error(f"unable to parse '{helm_chart_url}'. {str(e)}")
            errors = True
            continue

        for repo_charts in repo_charts['entries'].items():
            chart_name = repo_charts[0]
            if not any(chart for chart in ansible_helm_charts_matching if chart['name'] == chart_name):
                continue
            versions = []
            ansible_chart_version = [chart['version'] for chart in ansible_helm_charts_matching if
                                     chart['name'] == chart_name]
            ansible_chart_version = ansible_chart_version[0]
            for repo_chart in repo_charts[1]:
                if not semver.VersionInfo.isvalid(repo_chart['version'].lstrip('v')):
                    logging.warning(f"helm chart '{repo_chart['name']}' has an invalid "
                                    f"version '{repo_chart['version']}'")
                    continue
                version = semver.VersionInfo.parse(repo_chart['version'].lstrip('v'))
                if version.prerelease and not enable_prereleases:
                    logging.debug(f"skipping version '{repo_chart['version']}' of helm chart '{repo_chart['name']}' "
                                  f"because it is a pre-release")
                    continue
                logging.debug(f"found version '{repo_chart['version']}' of "
                              f"helm chart '{repo_chart['name']}'")
                versions.extend([repo_chart['version']])

            clean_versions = [version.lstrip('v') for version in versions]
            latest_version = str(max(map(semver.VersionInfo.parse, clean_versions)))

            latest_version = [version for version in versions if latest_version in version]

            if semver.match(latest_version[0].lstrip('v'), f">{ansible_chart_version.lstrip('v')}"):
                repo_chart = {
                    'name': chart_name,
                    'old_version': ansible_chart_version,
                    'new_version': latest_version[0]
                }
                chart_updates.append(repo_chart)
                logging.info(f"found update for helm chart '{repo_chart['name']}': "
                             f"'{ansible_chart_version}' to '{latest_version[0]}'")
                continue
            logging.debug(f"no update found for helm chart '{repo_charts[0]}'. "
                          f"current version in ansible helm task is '{ansible_chart_version}'")


def send_slack(msg, slack_token, slack_channel):
    try:
        slack_client = WebClient(token=slack_token)
        slack_client.chat_postMessage(channel=slack_channel,
                                      text=msg)
    except SlackApiError:
        raise


def main():
    try:
        env_vars = check_env_vars()
    except Exception as e:
        sys.stderr.write(f"{str(e)}\n")
        sys.exit(1)

    try:
        setup_logger(loglevel=env_vars.loglevel)
    except Exception as e:
        logging.critical(f"cannot setup logger. {e}")
        sys.exit(1)

    try:
        additional_vars = None
        if env_vars.vars_file:
            if not os.path.exists(env_vars.vars_file):
                raise FileNotFoundError(f"vars file '{env_vars.vars_file}' not found")

            with open(env_vars.vars_file) as stream:
                additional_vars = yaml.safe_load(stream)
    except Exception as e:
        logging.critical(f"unable to process extra vars yaml. {str(e)}")
        sys.exit(1)

    try:
        process_yaml(search_dir=env_vars.search_dir,
                     additional_vars=additional_vars,
                     enable_prereleases=env_vars.enable_prereleases)
    except Exception as e:
        logging.critical(f"unable to process ansible yaml. {str(e)}")
        sys.exit(1)

    try:
        get_chart_updates(enable_prereleases=env_vars.enable_prereleases)
    except Exception as e:
        logging.critical(f"unable to process charts. {str(e)}")
        sys.exit(1)

    if chart_updates:
        text = [f"The following chart update{'s are' if len(chart_updates) > 1 else ' is'} available:"]
        text.extend([f"{chart_update['name']}: `{chart_update['old_version']}` -> "
                     f"`{chart_update['new_version']}`" for chart_update in chart_updates])
        text = '\n'.join(text)

        try:
            send_slack(msg=text,
                       slack_token=env_vars.slack_token,
                       slack_channel=env_vars.slack_channel)
        except SlackApiError as e:
            logging.critical(f"unable to send slack notification. {e.response['error']}")
            sys.exit(1)

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
