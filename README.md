# Helminator

## TL;DR

Helminator scans your Ansible roles for Helm repositories and versions.
It then checks if there is an update to a given Helm chart availible and sends out a Slack notification.

## Requirements

- Ansible Playbook
- [Ansible Kubernetes Community collection](https://github.com/ansible-collections/community.kubernetes)
- Kubernetes Cluster
- GitLab
- Slack App

## Configration

In the examples directory you can find an example playbook including the required GitLab Ci configuration.

Helminator takes the following environment variables:

|Variable|Description|Example|
|:--------|:-----------|:-------|
|`HELMINATOR_ROOT_DIR`|Directory to scan|`/path/to/playbook`|
|`HELMINATOR_SLACK_API_TOKEN`|Slack API Token|`xorb-abc-def`|
|`HELMINATOR_SLACK_CHANNEL`|Slack channel to send message to|`#kubernetes`|

### Slack App

To receive Slack notifications you have to create a Slack App. Please refer to the [this guide](https://github.com/slackapi/python-slackclient/blob/master/tutorial/01-creating-the-slack-app.md).
