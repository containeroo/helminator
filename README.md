# Helminator

![Docker Image Version (latest semver)](https://img.shields.io/docker/v/containeroo/helminator?style=flat-square)
![Docker Pulls](https://img.shields.io/docker/pulls/containeroo/helminator?style=flat-square)
![Docker Image Size (tag)](https://img.shields.io/docker/image-size/containeroo/helminator/latest?style=flat-square)
![Docker Cloud Automated build](https://img.shields.io/docker/cloud/automated/containeroo/helminator?style=flat-square)
![Docker Cloud Build Status](https://img.shields.io/docker/cloud/build/containeroo/helminator?style=flat-square)
![GitHub issues](https://img.shields.io/github/issues/containeroo/helminator?style=flat-square)
![Twitter Follow](https://img.shields.io/twitter/follow/containeroo?style=social)

## Introduction

Helminator scans your Ansible playbook for helm and helm_repository tasks.
It then checks if there is an update to any of the defined Helm charts available. If configured, it creates a branch and merge request and can also sends out a Slack notification.
Helminator is built to run in a CI environment (e.g. GitLab CI).

## Requirements

- Ansible Playbook
- [Ansible Kubernetes Community collection](https://github.com/ansible-collections/community.kubernetes)
- Kubernetes Cluster
- GitLab
- Slack App

## Configration

In the examples directory you can find an example playbook including the required GitLab CI configuration.

Helminator takes the following environment variables:

| Variable                        | Description                                         | Example                                                |
| :------------------------------ | :-------------------------------------------------- | :----------------------------------------------------- |
| `HELMINATOR_ROOT_DIR`           | Directory to scan                                   | `CI_PROJECT_DIR`                                       |
| `HELMINATOR_ENABLE_PRERELEASES` | Enable pre-release processing (defaults to `false`) | `true` or `false`                                      |
| `HELMINATOR_LOGLEVEL`           | Set loglevel (defaults to `info`)                   | one of `critical`, `error`, `warning`, `info`, `debug` |
| `HELMINATOR_VARS_FILE`          | path to file with extra variables                   | `${CI_PROJECT_DIR}/vars/main.yml`                      |
| `HELMINATOR_VERIFY_SSL`         | verify ssl certificate (defaults to `true`)         | `true` or `false`                                      |
| `HELMINATOR_SLACK_API_TOKEN`    | Slack API Token                                     | `xorb-abc-def`                                         |
| `HELMINATOR_SLACK_CHANNEL`      | Slack channel to send message to                    | `#kubernetes`                                          |
| `GITLAB_TOKEN`                  | token for access                                    | `12345678`                                             |

### Slack App

To receive Slack notifications you have to create a Slack App. Please refer to [this guide](https://github.com/slackapi/python-slackclient/blob/master/tutorial/01-creating-the-slack-app.md).

## Usage

Ansible Playbook example: [playbook-k8s](https://github.com/containeroo/playbook-k8s)

### GitLab

If you want to use Helminator in a GitLab CI / CD job, you can use the follwing `.gitlab-ci.yml` as an example:

```yaml
image:
  name: containeroo/helminator:latest
  entrypoint: [""]

stages:
  - helminator

helminator:
  stage: helminator
  only:
    - schedules
  script: python /app/helminator.py
```

In order to set the configration environment variables, go to your project (repository) containing the playbook.  
Go to `Settings` -> `CI / CD` -> `Variabels` -> `Expand`.

After you have set all variables you can create a pipeline schedule. This ensures your job runs regularly.
