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
                                       'loglevel'
                                       ]
                          )
    return Env_vars(search_dir, slack_token, slack_channel, loglevel)


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


def process_yaml(search_dir):
    """iterate over directory and extract Helm chart name and version

    Arguments:
        search_dir {str} -- path to directory
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
            get_ansible_helm(path=item.absolute())
        except Exception as e:
            logging.error("unexpected exception while parsing yaml "
                          f"'{item.absolute}'. {str(e)}")


def get_ansible_helm(path):
    """load ansible yamls and search for Helm chart name and version

    Arguments:
        path {str} -- path to yaml
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
                chart_name = segments[-1]
                chart_version = task['community.kubernetes.helm'].get('chart_version')
                chart = {
                    'name': chart_name,
                    'version': chart_version
                }
                logging.debug(f"found chart '{chart_name}' in ansible with version '{chart_version}'")
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
                logging.debug(f"found chart repository '{repo_name}' in ansible with url '{repo_url}'")
                ansible_chart_repos.append(repo)


def get_chart_updates():
    """get Helm chart yaml from repo and compare chart name and version with ansible
    chart name and version
    """
    global errors
    for ansible_chart_repo in ansible_chart_repos:
        logging.debug(f"processing helm repository '{ansible_chart_repo['url']}'")
        try:
            helm_chart_url = f"{ansible_chart_repo['url']}/index.yaml"
            repo_response = requests.get(url=helm_chart_url)
        except Exception as e:
            logging.error(f"unable to fetch Helm chart '{helm_chart_url}'. {str(e)}")
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
            latest_version = "0.0.1"
            for repo_chart in repo_charts[1]:
                if not any(c for c in ansible_helm_charts if c['name'] == repo_chart['name']):
                    break
                if not semver.VersionInfo.isvalid(repo_chart['version']):
                    logging.warning(f"helm chart '{repo_chart['name']}' has an invalid "
                                    f"version '{repo_chart['version']}'")
                    break
                ansible_chart_version = [charts['version'] for charts in ansible_helm_charts if
                                         charts['name'] == repo_chart['name']]
                ansible_chart_version = ansible_chart_version[0]
                if not ansible_chart_version:
                    logging.error(f"{repo_chart['name']} has no 'chart_version'")
                    errors = True
                    break
                if not semver.VersionInfo.isvalid(ansible_chart_version):
                    logging.warning(f"chart '{repo_chart['name']}' in ansible has an invalid "
                                    f"version '{ansible_chart_version}'")
                    break
                if semver.match(f"{ansible_chart_version}", f">={repo_chart['version']}"):
                    logging.debug(f"ignoring version '{repo_chart['version']}' of "
                                  f"helm chart '{repo_chart['name']}'. current version "
                                  f"defined in ansible is '{ansible_chart_version}'")
                    continue
                if semver.match(f"{latest_version}", f">={repo_chart['version']}"):
                    continue
                latest_version = repo_chart['version']

                repo_chart = {
                    'name': repo_chart['name'],
                    'old_version': ansible_chart_version,
                    'new_version': latest_version
                }
                chart_updates.append(repo_chart)
                logging.info(f"found update for chart '{repo_chart['name']}': "
                             f"{ansible_chart_version} -> {latest_version}")


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
        process_yaml(search_dir=env_vars.search_dir)
    except Exception as e:
        logging.critical(f"unable to process ansible yaml. {str(e)}")
        sys.exit(1)

    try:
        get_chart_updates()
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
            logging.critical(f"unable to send Slack notification. {e.response['error']}")
            sys.exit(1)

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
