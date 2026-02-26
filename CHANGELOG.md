# Changelog

## [0.1.1] - 2026-02-26

### Fixed
- Fixed issue where only one SNMP strategy was tried per switch
- Added new database table for strategy caching
- Heavily modified fetch_oid_fast function for better compatibility
- Now tries all compatible strategies automatically
- Added optimization for known switches

### Changed
- Applied Ruff linting throughout codebase
- Replaced wildcard imports with explicit references
- Fixed undefined name errors

## [0.1.0] - 2026-02-06

### Added
- Initial public release
