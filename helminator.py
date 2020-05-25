import os
import sys
from pathlib import Path
from collections import namedtuple

try:
    import requests
    import semver
    import yaml
    from slack import WebClient
    from slack.errors import SlackApiError
except Exception as e:
    sys.stderr.write("requirenments are not satisified!")
    sys.exit(1)


ansible_chart_repos, ansible_helm_charts, chart_updates = [], [], []


def check_env_vars():
    search_dir = os.environ.get("HELMINATOR_ROOT_DIR")
    slack_token = os.environ.get("HELMINATOR_SLACK_API_TOKEN")
    slack_channel = os.environ.get("HELMINATOR_SLACK_CHANNEL")
    exclude_roles = os.environ.get("HELMINATOR_EXCLUDE_ROLES")

    if not search_dir:
        raise EnvironmentError("environment variable 'HELMINATOR_ROOT_DIR' not found!")
    
    if not slack_token:
        raise EnvironmentError("environment variable 'HELMINATOR_SLACK_API_TOKEN' not found!")

    if not slack_channel:
        raise EnvironmentError("environment variable 'HELMINATOR_SLACK_CHANNEL' not found!")

    Env_vars = namedtuple('Env_vars', ['search_dir', 'slack_token', 'slack_channel'])
    return Env_vars(search_dir, slack_token, slack_channel)

def get_ansible_helm(path):
    with open(path) as stream:
        tasks = yaml.safe_load(stream)

    for task in tasks:
        if task.get('community.kubernetes.helm'):
            if not any(
                    chart for chart in ansible_helm_charts if chart == task['community.kubernetes.helm']['chart_ref']):
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
            if not any(repo for repo in ansible_chart_repos
                       if repo['name'] == task['community.kubernetes.helm_repository']['name']):
                repo = {
                    'name': task['community.kubernetes.helm_repository']['name'],
                    'url': task['community.kubernetes.helm_repository']['repo_url']
                }
                ansible_chart_repos.append(repo)


def get_chart_updates():
    for ansible_chart_repo in ansible_chart_repos:
        repo_response = requests.get(url=f"{ansible_chart_repo['url']}/index.yaml")
        repo_charts = yaml.safe_load(repo_response.content)

        for repo_charts in repo_charts['entries'].items():
            latest_version = "0.0.1"
            for repo_chart in repo_charts[1]:
                if not any(c for c in ansible_helm_charts if c['name'] == repo_chart['name']):
                    continue
                if not semver.VersionInfo.isvalid(repo_chart['version']):
                    continue
                ansible_chart_version = [charts['version'] for charts in ansible_helm_charts if charts['name'] ==
                                         repo_chart['name']]
                ansible_chart_version = ansible_chart_version[0]
                if not ansible_chart_version:
                    sys.stderr.write(f"WARNING: {repo_chart['name']} has no 'chart_version'")
                    continue

                if not semver.VersionInfo.isvalid(ansible_chart_version):
                    continue
                if semver.match(f"{ansible_chart_version}", f">={repo_chart['version']}"):
                    continue
                if semver.match(f"{latest_version}", f">={repo_chart['version']}"):
                    continue
                latest_version = repo_chart['version']
                repo_chart = {
                    'name': repo_chart['name'],
                    'new_version': latest_version
                }
                chart_updates.append(repo_chart)


def send_slack(slack_token, slack_channel):
    slack_client = WebClient(token=slack_token)

    text = [f"Update for chart `{chart_update['name']}` available: version `{chart_update['new_version']}`"
            for chart_update in chart_updates]
    try:
        slack_client.chat_postMessage(channel=slack_channel,
                                        text='\n'.join(text))
    except SlackApiError as e:
        print(f"Got an error: {e.response['error']}")


def process_yaml(search_dir):
    for item in Path(search_dir).glob("**/*"):
        if not item.is_file():
            continue
        if item.suffix not in ['.yml']:
            continue
        get_ansible_helm(path=item.absolute())


def main():
    try:
        env_vars = check_env_vars()
    except Exception as e:
        sys.stderr.write(f"cannot process yamls. {e}")
        sys.exit(1)
    
    try:
        process_yaml(search_dir=env_vars.search_dir)
    except Exception as e:
        sys.stderr.write(f"cannot process yamls. {e}")
        sys.exit(1)

    try:
        get_chart_updates()
    except Exception as e:
        sys.stderr.write(f"cannot fetch charts. {e}")
        sys.exit(1)

    if chart_updates:
        try:
            send_slack(slack_token=env_vars.slack_token, slack_channel=env_vars.slack_channel)
        except Exception as e:
            sys.stderr.write(f"cannot send slack. {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
