## [v1.5.0](https://github.com/containeroo/helminator/tree/v1.5.0) (2020-08-XX)

[All Commits](https://github.com/containeroo/helminator/compare/v1.4.0...v1.5.0)

**New features:**

- Add support for tasks with or without FQCN: eg. `helm` instead of `community.kubernetes.helm`

**Dependencies:**

- Updated dependencies

**Other changes:**

- Moved `examples/` directory to seperate GitHub repository

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
