# Changelog

## [v2.1.1](https://github.com/containeroo/helminator/tree/v2.1.1) (202X-XX-XX)

[All Commits](https://github.com/containeroo/helminator/compare/v2.1.0...v2.1.1)

**Bug fixes:**

- if updating an existing merge request, labels will not be checked
- update exceptions
- fix merge request url
- fix getting file path for Gitlab repo

## [v2.1.0](https://github.com/containeroo/helminator/tree/v2.1.0) (2020-12-14)

[All Commits](https://github.com/containeroo/helminator/compare/v2.0.3...v2.1.0)

**New features:**

- new variables:
  - `HELMINATOR_GITLAB_LABELS`: Add labels to merge request

**Bug fixes:**

- fix check for existing mergere request
- fix typos
- update docstrings

## [v2.0.3](https://github.com/containeroo/helminator/tree/v2.0.3) (2020-12-12)

[All Commits](https://github.com/containeroo/helminator/compare/v2.0.2...v2.0.3)

**Bug fixes:**

- fix detecting existing merge requests

## [v2.0.2](https://github.com/containeroo/helminator/tree/v2.0.2) (2020-12-12)

[All Commits](https://github.com/containeroo/helminator/compare/v2.0.1...v2.0.2)

**Bug fixes:**

- fix hyperlink in Slack message
- fix varous typos

## [v2.0.1](https://github.com/containeroo/helminator/tree/v2.0.1) (2020-12-11)

[All Commits](https://github.com/containeroo/helminator/compare/v1.7.1...v2.0.1)

**New features:**

- Slack message contains a link to the related merge request
- new variables:
  - `HELMINATOR_GITLAB_REMOVE_SOURCE_BRANCH` -> Delete source branch when merge request is accepted
  - `HELMINATOR_GITLAB_SQUASH_COMMITS` -> Squash commits when merge request is accepted

**Bug fixes:**

- various improvements

### Changes from v2.0.0

**New features:**

- Introducing pull requests:
  - create a pull request when an update is found
  - assign pull request to one or more users
  - update existing pull requests when a new update is found
  - skip updating by closing the pull request
- Added the ability to disable SSL verification (e.g. when behind a corporate proxy)

**Dependencies:**

- Update requests to v2.25.0 (#42)
- Update semver to v2.14.0 (#40)
- Update slackclient to v2.9.3 (#41)

**Bug fixes:**

- minor bugfixes
- typos

## [v1.7.1](https://github.com/containeroo/helminator/tree/v1.7.1) (2020-10-12)

[All Commits](https://github.com/containeroo/helminator/compare/v1.7.0...v1.7.1)

**New features:**

- If loglevel `debug` is set, log also filename, line number and function name

**Bug fixes:**

- Skip variables during extracting ansible helm repository tasks if not used with `with_items`

**Dependencies:**

- Updated slackclient dependency (#39)

## [v1.7.0](https://github.com/containeroo/helminator/tree/v1.7.0) (2020-10-03)

[All Commits](https://github.com/containeroo/helminator/compare/v1.6.1...v1.7.0)

**New features:**

- Add support for ansible blocks

## [v1.6.1](https://github.com/containeroo/helminator/tree/v1.6.1) (2020-09-28)

[All Commits](https://github.com/containeroo/helminator/compare/v1.6.0...v1.6.1)

**Bug fixes:**

- Fix script crash when `HELMINATOR_VARS_FILE` is unset (#34)

## [v1.6.0](https://github.com/containeroo/helminator/tree/v1.6.0) (2020-09-27)

[All Commits](https://github.com/containeroo/helminator/compare/v1.5.2...v1.6.0)

**New features:**

- Add support for variables in `with_items` tasks
- New optional environment variable `HELMINATOR_VARS_FILE` to define an Ansible vars file

**Dependencies:**

- Updated slackclient dependency (#32)

## [v1.5.2](https://github.com/containeroo/helminator/tree/v1.5.2) (2020-09-14)

[All Commits](https://github.com/containeroo/helminator/compare/v1.5.1...v1.5.2)

**Dependencies:**

- Updated slackclient dependency (#30)

## [v1.5.1](https://github.com/containeroo/helminator/tree/v1.5.1) (2020-08-10)

[All Commits](https://github.com/containeroo/helminator/compare/v1.5.0...v1.5.1)

**Improvements:**

- Use unused `send_slack` function

**Dependencies:**

- Updated slackclient dependency (#28)
- Docker image now uses python 3.8 (#27)

## [v1.5.0](https://github.com/containeroo/helminator/tree/v1.5.0) (2020-08-04)

[All Commits](https://github.com/containeroo/helminator/compare/v1.4.0...v1.5.0)

**New features:**

- Add support for tasks with or without FQCN: eg. `helm` instead of `community.kubernetes.helm`

**Improvements:**

- Show `repo_name/chart_name` in log output instead of just the chart name: eg. `argo/argo-cd` instead of `argo-cd`

**Bug fixes:**

- Skip `collections` folder

**Dependencies:**

- Updated dependencies

**Other changes:**

- Moved `examples/` directory to separate GitHub repository

## [v1.4.0](https://github.com/containeroo/helminator/tree/v1.4.0) (2020-07-30)

[All Commits](https://github.com/containeroo/helminator/compare/v1.3.1...v1.4.0)

**New features:**

- Add support for `with_items` in `community.kubernetes.helm_repository` tasks

## [v1.3.1](https://github.com/containeroo/helminator/tree/v1.3.1) (2020-07-07)

[All Commits](https://github.com/containeroo/helminator/compare/v1.3.0...v1.3.1)

**Bug fixes:**

- Helm repo urls with a trailing slash are now parsed correctly (#21)

## [v1.3.0](https://github.com/containeroo/helminator/tree/v1.3.0) (2020-06-26)

[All Commits](https://github.com/containeroo/helminator/compare/v1.2.1...v1.3.0)

**Bug fixes:**

- Version strings beginning with a `v` (e.g. `v1.0.0`) now work (#17)

**New features:**

- Add optional `HELMINATOR_ENABLE_PRERELEASES` environment variable to enable or disable processing of pre-releases (#16)

## [v1.2.1](https://github.com/containeroo/helminator/tree/v1.2.1) (2020-06-24)

[All Commits](https://github.com/containeroo/helminator/compare/v1.2.0...v1.2.1)

**Improvements:**

- Fix small typos

**Dependencies:**

- Updated dependencies

## [v1.2.0](https://github.com/containeroo/helminator/tree/v1.2.0) (2020-06-24)

[All Commits](https://github.com/containeroo/helminator/compare/v1.1.0...v1.2.0)

**Improvements:**

- Skip prerelease versions (#12)
- Improved version processing (#11)
- Fix small typos
- Add CHANGELOG

## [v1.1.0](https://github.com/containeroo/helminator/tree/v1.1.0) (2020-06-05)

[All Commits](https://github.com/containeroo/helminator/compare/v1.0.0...v1.1.0)

**Improvements:**

- Slack notifications (#7)
- Console logging (#8)

**New features:**

- Added optional `HELMINATOR_LOGLEVEL` environment variable

## [v1.0.0](https://github.com/containeroo/helminator/tree/v1.0.0) (2020-06-05)

Initial release
