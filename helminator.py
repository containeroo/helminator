import os
import logging
import logging.handlers
import sys

from collections import namedtuple
from pathlib import Path

ansible_chart_repos, ansible_helm_charts, chart_updates = [], [], []
errors = False

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
                                       'enable_prereleases'
                                       ]
                          )
    return Env_vars(search_dir, slack_token, slack_channel, loglevel, enable_prereleases)


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

    default_format = logging.Formatter(
        "%(asctime)s [%(levelname)-7.7s] %(message)s")
    console_logger = logging.StreamHandler(sys.stdout)
    console_logger.setLevel(loglevel)
    console_logger.setFormatter(default_format)
    root_logger.addHandler(console_logger)


def process_yaml(search_dir, enable_prereleases=False):
    """iterate over directory and extract Helm chart name and version

    Keyword Arguments:
        search_dir {str} -- path to directory
        enable_pre {bool} -- process pre-releases (default: False)
    """
    search_dir = Path(search_dir)
    if not search_dir.is_dir():
        raise NotADirectoryError(f"'{search_dir}' is not a directory")

    for item in search_dir.glob("**/*"):
        if not item.is_file():
            continue
        if item.suffix not in ['.yml', '.yaml']:
            continue
        try:
            get_ansible_helm(path=item.absolute(), enable_prereleases=enable_prereleases)
        except Exception as e:
            logging.error("unexpected exception while parsing yaml "
                          f"'{item.absolute}'. {str(e)}")


def get_ansible_helm(path, enable_prereleases=False):
    """load ansible yamls and search for Helm chart name and version

    Keyword Arguments:
        path {str} -- path to yaml
        enable_pre {bool} -- process pre-releases (default: False)
    """
    try:
        with open(path) as stream:
            tasks = yaml.safe_load(stream)
    except Exception:
        # ignore unparsable yaml files, since ansible already does this
        return

    for task in tasks:
        if not isinstance(task, dict):
            continue
        if task.get('community.kubernetes.helm'):
            if not any(chart for chart in ansible_helm_charts if
                       chart == task['community.kubernetes.helm']['chart_ref']):
                segments = task['community.kubernetes.helm']['chart_ref'].split('/')
                if len(segments) > 2:
                    continue
                repo_name = segments[0]
                chart_name = segments[-1]
                chart_version = task['community.kubernetes.helm'].get('chart_version')
                if not chart_version or not semver.VersionInfo.isvalid(chart_version.lstrip('v')):
                    logging.warning(f"ansible helm task '{chart_name}' has an invalid "
                                    f"version '{chart_version}'")
                    continue
                version = semver.VersionInfo.parse(chart_version.lstrip('v'))
                if version.prerelease and not enable_prereleases:
                    logging.warning(f"skipping ansible helm task '{chart_name}' with version '{chart_version}' because"
                                    " it is a pre-release")
                    continue
                chart = {
                    'name': chart_name,
                    'version': chart_version,
                    'repo': repo_name
                }
                logging.debug(f"found ansible helm task '{chart_name}' with version '{chart_version}'")
                ansible_helm_charts.append(chart)
            continue

        if task.get('community.kubernetes.helm_repository'):
            if not any(repo for repo in ansible_chart_repos if
                       repo['name'] == task['community.kubernetes.helm_repository']['name']):
                repo_name = task['community.kubernetes.helm_repository']['name']
                repo_url = task['community.kubernetes.helm_repository']['repo_url']
                repo = {
                    'name': repo_name,
                    'url': repo_url
                }
                logging.debug(f"found ansible helm_repository task '{repo_name}' with url '{repo_url}'")
                ansible_chart_repos.append(repo)


def get_chart_updates(enable_prereleases=False):
    """get Helm chart yaml from repo and compare chart name and version with ansible
    chart name and version

    Keyword Arguments:
         enable_pre {bool} -- process pre-releases (default: False)
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
    except SlackApiError as e:
        pass


def main():
    try:
        env_vars = check_env_vars()
    except Exception as e:
        sys.stderr.write(str(e))
        sys.exit(1)

    try:
        setup_logger(loglevel=env_vars.loglevel)
    except Exception as e:
        logging.critical(f"cannot setup logger. {e}")
        sys.exit(1)

    try:
        process_yaml(search_dir=env_vars.search_dir, enable_prereleases=env_vars.enable_prereleases)
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
            slack_client = WebClient(token=env_vars.slack_token)
            slack_client.chat_postMessage(channel=env_vars.slack_channel,
                                          text=text)
        except SlackApiError as e:
            logging.critical(f"unable to send slack notification. {e.response['error']}")
            sys.exit(1)

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
