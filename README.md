# Helminator

# DEPRECIATION WARNING

In favor of [Renovate regex](https://docs.renovatebot.com/modules/manager/regex/) this project wil not be maintained anymore.

here is an example how renovate will check if a helm chart update is available:

tasks/argocd.yml

```yaml
---
- name: Install helm chart argocd
  helm:
    name: argocd
    # renovate: datasource=helm
    chart_repo_url: https://argoproj.github.io/argo-helm
    chart_ref: argo-cd
    chart_version: 3.2.2
    create_namespace: true
    release_namespace: "{{ argocd_namespace }}"
    values: "{{ lookup('template', 'argocd/argocd-values.yaml') | from_yaml }}"
```

renovate.json:

```json
{
    "ignorePaths": [
        "collections/**"
    ],
    "assignees": [
        "YOUR USER NAME"
    ],
    "packageRules": [
        {
            "datasources": [
                "galaxy",
                "helm"
            ],
            "updateTypes": [
                "major"
            ],
            "enabled": true
        }
    ],
    "regexManagers": [
        {
            "fileMatch": [
                "tasks\/.*\\.yml"
            ],
            "matchStrings": [
                "datasource=(?<datasource>.*?)\\s.*chart_repo_url: (?<registryUrl>.*?)\\s.* chart_ref: (?<depName>.*?)\\s.*?chart_version: (?<currentValue>.*)\\s"
            ],
            "versioningTemplate": "{{#if versioning}}{{{versioning}}}{{else}}semver{{/if}}"
        }
    ],
    "separateMajorMinor": false,
    "labels": [
        "renovate"
    ]
}
```

![Docker Image Version (latest semver)](https://img.shields.io/docker/v/containeroo/helminator?style=flat-square)
![Docker Pulls](https://img.shields.io/docker/pulls/containeroo/helminator?style=flat-square)
![Docker Image Size (tag)](https://img.shields.io/docker/image-size/containeroo/helminator/latest?style=flat-square)
![GitHub issues](https://img.shields.io/github/issues/containeroo/helminator?style=flat-square)
![Twitter Follow](https://img.shields.io/twitter/follow/containeroo?style=social)

## Introduction

Helminator scans your Ansible playbook for helm and helm_repository tasks.
It then checks if there is an update to any of the defined Helm charts available. If configured, it creates a branch and merge request and/or send out a Slack notification.
Helminator is built to run in a CI environment (e.g. GitLab CI).

## Requirements

- Ansible Playbook
- [Ansible Kubernetes Community collection](https://github.com/ansible-collections/community.kubernetes)
- Kubernetes Cluster
- GitLab
- Slack App (optional)

## Configration

In the examples directory you can find an example playbook including the required GitLab CI configuration.

Helminator takes the following environment variables:

| Variable                                 | Description                                                                                                          | Example                                                |
| :--------------------------------------- | :------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------- |
| `HELMINATOR_ANSIBLE_ROOT_DIR`            | Directory to scan (defaults to `CI_PROJECT_DIR`)                                                                     | `ansible/`                                             |
| `HELMINATOR_ANSIBLE_VARS_FILE`           | Path to file with extra variables                                                                                    | `vars/main.yml`                                        |
| `HELMINATOR_ENABLE_PRERELEASES`          | Enable pre-release processing (defaults to `false`)                                                                  | `true` or `false`                                      |
| `HELMINATOR_VERIFY_SSL`                  | Verify ssl certificate (defaults to `true`)                                                                          | `true` or `false`                                      |
| `HELMINATOR_LOGLEVEL`                    | Set loglevel (defaults to `info`)                                                                                    | one of `critical`, `error`, `warning`, `info`, `debug` |
| `HELMINATOR_ENABLE_MERGEREQUESTS`        | Create for each chart update a merge request (defaults to `true`)                                                    | `true` or `false`                                      |
| `HELMINATOR_GITLAB_TOKEN`                | Gitlab access token (more detail see below)                                                                          | `12345678`                                             |
| `HELMINATOR_GITLAB_REMOVE_SOURCE_BRANCH` | Delete source branch when merge request is accepted (defaults to `true`)                                             | `true` or `false`                                      |
| `HELMINATOR_GITLAB_SQUASH_COMMITS`       | Squash commits when merge request is accepted (defaults to `false`)                                                  | `true` or `false`                                      |
| `HELMINATOR_GITLAB_AUTOMERGE`            | Accept merge request and close it (defaults to`false`)                                                               | `true` or `false`                                      |
| `HELMINATOR_GITLAB_MERGE_MAJOR`          | Automerge also major updates (defaults to`false`)                                                                    | `true` or `false`                                      |
| `HELMINATOR_GITLAB_ASSIGNEES`            | List of name of assignees, separate by a comma                                                                       | `user1,user2`                                          |
| `HELMINATOR_GITLAB_LABELS`               | List of labels to set on a merge request, separate by a comma. set it to "" for no labels (defaults to `helminator`) | `helm,update,k8s`                                      |
| `HELMINATOR_SLACK_API_TOKEN`             | Slack API Token                                                                                                      | `xorb-abc-def`                                         |
| `HELMINATOR_SLACK_CHANNEL`               | Slack channel to send message to                                                                                     | `#kubernetes`                                          |

*GITLAB_TOKEN*
*Add a user as member with role developer to a project and use his token.*

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
