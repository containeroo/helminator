import logging
import logging.handlers
import os
import sys
from collections import namedtuple
from io import StringIO
from pathlib import Path

try:
    import requests
    import semver
    import yaml
    from slack import WebClient
    from slack.errors import SlackApiError
except Exception as e:
    sys.stderr.write("requirenments are not satisified!")
    sys.exit(1)


ansible_chart_repos, ansible_helm_charts = [], []
slack_log = None


def check_env_vars():
    search_dir = os.environ.get("HELMINATOR_ROOT_DIR")
    slack_token = os.environ.get("HELMINATOR_SLACK_API_TOKEN")
    slack_channel = os.environ.get("HELMINATOR_SLACK_CHANNEL")
    exclude_roles = os.environ.get("HELMINATOR_EXCLUDE_ROLES")

    if not search_dir:
        raise EnvironmentError(
                "environment variable 'HELMINATOR_ROOT_DIR' not found!")

    if not slack_token:
        raise EnvironmentError(
                "environment variable 'HELMINATOR_SLACK_API_TOKEN' not found!")

    if not slack_channel:
        raise EnvironmentError(
                "environment variable 'HELMINATOR_SLACK_CHANNEL' not found!")

    Env_vars = namedtuple('Env_vars', ['search_dir',
                                       'slack_token',
                                       'slack_channel']
    )
    return Env_vars(search_dir, slack_token, slack_channel)


def setup_logger():
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # log to console
    console_logger = logging.StreamHandler(sys.stdout)
    console_logger.setLevel(logging.INFO)
    console_logger.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)-7.7s] %(message)s"))
    root_logger.addHandler(console_logger)

    # logger for slack
    global slack_log
    slack_log = StringIO()
    slack_logger = logging.StreamHandler(slack_log)
    slack_logger.setFormatter(
        logging.Formatter("%(message)s"))
    root_logger.addHandler(slack_logger)


def get_ansible_helm(path):
    try:
        with open(path) as stream:
            tasks = yaml.safe_load(stream)
    except Exception as e:
        logging.debug(f"cannot read '{path}'. {str(e)}")
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
                chart = {
                    'name': segments[-1],
                    'version': task['community.kubernetes.helm'].get('chart_version')
                }
                ansible_helm_charts.append(chart)
            continue

        if task.get('community.kubernetes.helm_repository'):
            if not any(repo for repo in ansible_chart_repos if
                       repo['name'] == task['community.kubernetes.helm_repository']['name']):
                repo = {
                    'name': task['community.kubernetes.helm_repository']['name'],
                    'url': task['community.kubernetes.helm_repository']['repo_url']
                }
                ansible_chart_repos.append(repo)


def get_chart_updates():
    for ansible_chart_repo in ansible_chart_repos:
        try:
            helm_chart_url = f"{ansible_chart_repo['url']}/index.yaml"
            repo_response = requests.get(url=helm_chart_url)

            if repo_response.status_code != 200:
                raise Exception(f"'{helm_chart_url}' returned: {str(e)}")
        except Exception as e:
            logging.error(f"cannot get Helm chart. {str(e)}")
            continue

        try:
            repo_charts = yaml.safe_load(repo_response.content)
        except Exception as e:
            logging.error(f"cannot read '{helm_chart_url}'. {str(e)}")
            continue

        for repo_charts in repo_charts['entries'].items():
            latest_version = "0.0.1"
            for repo_chart in repo_charts[1]:
                if not any(c for c in ansible_helm_charts if c['name'] == repo_chart['name']):
                    continue
                if not semver.VersionInfo.isvalid(repo_chart['version']):
                    continue
                ansible_chart_version = [charts['version'] for charts in ansible_helm_charts if
                                         charts['name'] == repo_chart['name']]
                ansible_chart_version = ansible_chart_version[0]
                if not ansible_chart_version:
                    logging.warning(f"{repo_chart['name']} has no 'chart_version'")
                    continue

                if not semver.VersionInfo.isvalid(ansible_chart_version):
                    continue
                if semver.match(f"{ansible_chart_version}", f">={repo_chart['version']}"):
                    continue
                if semver.match(f"{latest_version}", f">={repo_chart['version']}"):
                    continue
                latest_version = repo_chart['version']

                logging.info(f"Update for chart `{repo_chart['name']}` "
                             f"available: version `{latest_version}`")


def send_slack(msg, slack_token, slack_channel):
    try:
        slack_client = WebClient(token=slack_token)
        slack_client.chat_postMessage(channel=slack_channel,
                                      text=msg)
    except SlackApiError as e:
        raise SlackApiError(f"cannot send slack notification. {str(e)}")


def process_yaml(search_dir):
    for item in Path(search_dir).glob("**/*"):
        if not item.is_file():
            continue
        if item.suffix not in ['.yml', '.yaml']:
            continue
        try:
            get_ansible_helm(path=item.absolute())
        except Exception as e:
            logging.error(str(e))


def finish(success, msg, slack_token, slack_channel):
        try:
            send_slack(msg=msg,
                       slack_token=slack_token,
                       slack_channel=slack_channel)
        except Exception as e:
            logging.error(f"cannot send slack message. {e}")
            success = False
        sys.exit(0 if success else 1)


def main():
    try:
        env_vars = check_env_vars()
    except Exception as e:
        sys.stderr.write(f"ERROR: {str(e)}")
        sys.exit(1)

    try:
        setup_logger()
    except Exception as e:
        finish(success=False,
               msg=f"cannot setup logger. {str(e)}",
               slack_token=env_vars.slack_token,
               slack_channel=env_vars.slack_channel)

    try:
        process_yaml(search_dir=env_vars.search_dir)
    except Exception as e:
        finish(success=False,
               msg=slack_log.getvalue(),
               slack_token=env_vars.slack_token,
               slack_channel=env_vars.slack_channel)

    try:
        get_chart_updates()
    except Exception as e:
        finish(success=False,
               msg=slack_log.getvalue(),
               slack_token=env_vars.slack_token,
               slack_channel=env_vars.slack_channel)

    try:
        if slack_log.getvalue():
            finish(success=True,
                   msg=slack_log.getvalue(),
                   slack_token=env_vars.slack_token,
                   slack_channel=env_vars.slack_channel)
    except Exception as e:
        logging.error(f"cannot send Slack notification. {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
