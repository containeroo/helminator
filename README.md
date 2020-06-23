# Helminator

![Docker Image Version (latest semver)](https://img.shields.io/docker/v/containeroo/helminator?style=flat-square)
![Docker Pulls](https://img.shields.io/docker/pulls/containeroo/helminator?style=flat-square)
![Docker Image Size (tag)](https://img.shields.io/docker/image-size/containeroo/helminator/latest?style=flat-square)
![Docker Cloud Automated build](https://img.shields.io/docker/cloud/automated/containeroo/helminator?style=flat-square)
![Docker Cloud Build Status](https://img.shields.io/docker/cloud/build/containeroo/helminator?style=flat-square)
![GitHub issues](https://img.shields.io/github/issues/containeroo/helminator?style=flat-square)
![Twitter Follow](https://img.shields.io/twitter/follow/containeroo?style=social)

## TL;DR

Helminator scans your Ansible roles for Helm repositories and versions.
It then checks if there is an update to a given Helm chart available and sends out a Slack notification.

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
|`HELMINATOR_LOGLEVEL`|Set loglevel (defaults to `info`)|can either be `critical`, `error`, `warning`, `info`, `debug`|

### Slack App

To receive Slack notifications you have to create a Slack App. Please refer to the [this guide](https://github.com/slackapi/python-slackclient/blob/master/tutorial/01-creating-the-slack-app.md).
