import os
import sys
from collections import namedtuple
from pathlib import Path

# colors
GREEN = '\x1b[32m'
YELLOW = '\x1b[33m'
RED = '\x1b[31m'
REDDER = '\x1b[41m'
DEFAULT = '\x1b[0m'

ansible_chart_repos, ansible_helm_charts, chart_updates = [], [], []
errors = None

try:
    import requests
    import semver
    import yaml
    from slack import WebClient
    from slack.errors import SlackApiError
except Exception:
    sys.stderr.write(f"{REDDER}requirements are not satisfied! see 'requirements.txt'{DEFAULT}\n")
    sys.exit(1)


def write_fatal(msg):
    sys.stderr.write(f"{REDDER}FATAL: {msg}{DEFAULT}\n")
    sys.exit(1)


def write_error(msg):
    global errors
    errors = True
    sys.stderr.write(f"{RED}ERROR: {msg}{DEFAULT}\n")


def write_warning(msg):
    sys.stderr.write(f"{YELLOW}WARNING: {msg}{DEFAULT}\n")


def write_info(msg):
    sys.stdout.write(f"{GREEN}{msg}{DEFAULT}\n")


def check_env_vars():
    search_dir = os.environ.get("HELMINATOR_ROOT_DIR")
    slack_token = os.environ.get("HELMINATOR_SLACK_API_TOKEN")
    slack_channel = os.environ.get("HELMINATOR_SLACK_CHANNEL")

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
                                       'slack_channel']
    )
    return Env_vars(search_dir, slack_token, slack_channel)


def process_yaml(search_dir):
    """iterate over directory and extract Helm chart name and version

    Arguments:
        search_dir {string} -- path to directory
    """
    search_dir = Path(search_dir)
    if not search_dir.is_dir():
        write_fatal(f"'{search_dir}' is not a directory")

    for item in search_dir.glob("**/*"):
        if not item.is_file():
            continue
        if item.suffix not in ['.yml', '.yaml']:
            continue
        try:
            get_ansible_helm(path=item.absolute())
        except Exception as e:
            write_error("unexpected exception while parsing yaml "
                        f"'{item.absolute}'. {str(e)}")


def get_ansible_helm(path):
    """load ansible yamls and search for Helm chart name and version

    Arguments:
        path {string} -- path to yaml
    """
    try:
        with open(path) as stream:
            tasks = yaml.safe_load(stream)
    except yaml.YAMLError:
        # skip invalid yamls, like templates
        return
    except Exception as e:
        write_warning(f"unable to parse '{path}'. {e.problem}\n")
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
    """get Helm chart yaml from repo and compare chart name and version with ansible
    chart name and version
    """
    for ansible_chart_repo in ansible_chart_repos:
        try:
            helm_chart_url = f"{ansible_chart_repo['url']}/index.yaml"
            repo_response = requests.get(url=helm_chart_url)
        except Exception as e:
            write_error(f"unable to fetch Helm chart '{helm_chart_url}'. {str(e)}")
            continue
        
        if repo_response.status_code != 200:
            write_error(f"'{helm_chart_url}' returned: {str(e)}")
            continue

        try:
            repo_charts = yaml.safe_load(repo_response.content)
        except Exception as e:
            write_error(f"unable to parse '{helm_chart_url}'. {str(e)}")
            continue

        for repo_charts in repo_charts['entries'].items():
            latest_version = "0.0.1"
            for repo_chart in repo_charts[1]:
                if not any(c for c in ansible_helm_charts if c['name'] == repo_chart['name']):
                    break
                if not semver.VersionInfo.isvalid(repo_chart['version']):
                    break
                ansible_chart_version = [charts['version'] for charts in ansible_helm_charts if
                                         charts['name'] == repo_chart['name']]
                ansible_chart_version = ansible_chart_version[0]
                if not ansible_chart_version:
                    write_error(f"{repo_chart['name']} has no 'chart_version'")
                    break
                if not semver.VersionInfo.isvalid(ansible_chart_version):
                    break
                if semver.match(f"{ansible_chart_version}", f">={repo_chart['version']}"):
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


def send_slack(msg, slack_token, slack_channel):
    try:
        slack_client = WebClient(token=slack_token)
        slack_client.chat_postMessage(channel=slack_channel,
                                      text=msg)
    except SlackApiError as e:
        raise SlackApiError(f"unable to send slack notification. {str(e)}")


def main():
    try:
        env_vars = check_env_vars()
    except Exception as e:
        write_fatal(e)

    try:
        process_yaml(search_dir=env_vars.search_dir)
    except Exception as e:
        write_fatal(f"unable to process yaml. {str(e)}")

    try:
        get_chart_updates()
    except Exception as e:
        write_fatal(f"unable to process yaml. {str(e)}")

    if chart_updates:
        text = [f"Update for chart `{chart_update['name']}` available: "
                f"version `{chart_update['old_version']}` -> "
                f"`{chart_update['new_version']}`" for chart_update in chart_updates]
        text = '\n'.join(text)
        write_info(text)

        try:
            slack_client = WebClient(token=env_vars.slack_token)
            slack_client.chat_postMessage(channel=env_vars.slack_channel,
                                          text=text)
        except SlackApiError as e:
            write_fatal(f"unable to send Slack notification. {e.response['error']}")

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
