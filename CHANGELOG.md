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
