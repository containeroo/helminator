import yaml
import semver
import requests
from slack import WebClient
from slack.errors import SlackApiError
from pathlib import Path
import os

ansible_chart_repos = []
ansible_helm_charts = []
chart_updates = []

search_dir = os.environ.get("HELMINATOR_ROOT_DIR")
slack_client = WebClient(token=os.environ['HELMINATOR_SLACK_API_TOKEN'])
slack_channel = os.environ.get("HELMINATOR_SLACK_CHANNEL")


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
                ansible_version = [charts['version'] for charts in ansible_helm_charts if charts['name'] ==
                                   repo_chart['name']]
                if not semver.VersionInfo.isvalid(ansible_version[0]):
                    continue
                if semver.match(f"{ansible_version[0]}", f">={repo_chart['version']}"):
                    continue
                if semver.match(f"{latest_version}", f">={repo_chart['version']}"):
                    continue
                latest_version = repo_chart['version']
                repo_chart = {
                    'name': repo_chart['name'],
                    'new_version': latest_version
                }
                chart_updates.append(repo_chart)


def main():
    for item in Path(search_dir).glob("**/*"):
        if not item.is_file():
            continue
        if item.suffix not in ['.yml']:
            continue
        get_ansible_helm(path=item.absolute())

    get_chart_updates()

    if chart_updates:
        text = [f"Update for chart `{chart_update['name']}` available: version `{chart_update['new_version']}`"
                for chart_update in chart_updates]
        try:
            slack_client.chat_postMessage(channel=slack_channel,
                                          text='\n'.join(text))
        except SlackApiError as e:
            print(f"Got an error: {e.response['error']}")


if __name__ == "__main__":
    main()
