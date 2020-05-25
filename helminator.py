import yaml
import semver
import requests
from slack import WebClient
from slack.errors import SlackApiError
from pathlib import Path
import os

chart_repos = []
mycharts = []
new_updates = []

rootdir = os.environ.get("HELMINATOR_ROOT_DIR")
client = WebClient(token=os.environ['HELMINATOR_SLACK_API_TOKEN'])
channel = os.environ.get("HELMINATOR_SLACK_CHANNEL")


def get_helm_charts(path):
    with open(path) as stream:
        ymlfile = yaml.safe_load(stream)

    for i in ymlfile:
        if i.get('community.kubernetes.helm'):
            if not any(chart for chart in mycharts if chart == i['community.kubernetes.helm']['chart_ref']):
                segments = i['community.kubernetes.helm']['chart_ref'].split('/')
                if len(segments) > 2:
                    continue
                chart = {
                    'name': segments[-1],
                    'version': i['community.kubernetes.helm'].get('chart_version')
                }

                mycharts.append(chart)


def get_repo_urls(path):
    with open(path) as stream:
        ymlfile = yaml.safe_load(stream)

    for i in ymlfile:
        if i.get('community.kubernetes.helm_repository'):
            if not any(repo for repo in chart_repos if repo['name'] == i['community.kubernetes.helm_repository']['name']):
                repo = {
                    'name': i['community.kubernetes.helm_repository']['name'],
                    'url': i['community.kubernetes.helm_repository']['repo_url']
                }

                response = requests.get(url=f"{repo['url']}/index.yaml")
                chartyml = yaml.safe_load(response.content)

                for charts in chartyml['entries'].items():
                    latest_version = "0.0.1"
                    for chart in charts[1]:
                        if not any(c for c in mycharts if c['name'] == chart['name']):
                            continue
                        if not semver.VersionInfo.isvalid(chart['version']):
                            continue
                        ansible_version = [charts['version'] for charts in mycharts if charts['name'] == chart['name']]
                        if not semver.VersionInfo.isvalid(ansible_version[0]):
                            continue
                        if semver.match(f"{ansible_version[0]}", f">={chart['version']}"):
                            continue
                        if semver.match(f"{latest_version}", f">={chart['version']}"):
                            continue
                        latest_version = chart['version']
                        chart = {
                            'name': chart['name'],
                            'new_version': latest_version
                        }
                        new_updates.append(chart)
                chart_repos.append(repo)


for item in Path(rootdir).glob("**/*"):
    if not item.is_file():
        continue
    if item.suffix not in ['.yml']:
        continue
    get_helm_charts(path=item.absolute())

for item in Path(rootdir).glob("**/*"):
    if not item.is_file():
        continue
    excludes = ['prometheus-operator', 'minio-backup', 'local-path-provisioner', 'nfs-client-provisioner']
    if any(entry for entry in excludes if entry in item.parts):
        continue
    if item.suffix not in ['.yml']:
        continue
    get_repo_urls(path=item.absolute())

if new_updates:
    text = [f"Update for chart `{update['name']}` available: version `{update['new_version']}`" for update in new_updates]
    try:
        response = client.chat_postMessage(
            channel=channel,
            text='\n'.join(text))
    except SlackApiError as e:
        assert e.response["ok"] is False
        assert e.response["error"]
        print(f"Got an error: {e.response['error']}")
