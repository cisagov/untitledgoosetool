# Untitled Goose Tool Change Log

All notable changes to this project will be documented in this file.

## [1.2.0] - The goose is loose - 2023-04-21
### Added
- Implemented delegated application authentication.
- Implemented support for more MFA methods: number matching push notification, app OTP code, and SMS OTP code.

### Changed
- Added more debugging statements for `goosey auth --debug`.

### Fixed
- Implemented monkey patch for `goosey-gui` on Windows machines.
- Fixed logic for errorneous token check when `m365` in the `.conf` was set to `False`.

## [1.1.1] - The goose is loose - 2023-04-12
### Added
- Readme prerequisites regarding Microsoft Visual C++ redistributable package (14.x) for Windows machines

### Changed
- Updated selenium logic regarding push notification MFA prompts. It will detect if MFA was never accepted and exit.

### Fixed
- Implemented more checks for the .ugt_file to see if cookies and tokens are correctly exported.
- Updated certain AzureAD call outputs, making it easier for users to track call results.

## [1.1.0] - The goose is loose - 2023-04-05
### Added
- Implemented file encryption for credential file(s) with the `--secure` parameter.
- Added more authentication expiration checks and implemented better logic for handling an expired authentication token/cookie.
- Added more logging for `goosey auth` and `goosey auth --debug`.
- Added support for Python 3.10.

### Changed
- Separated .conf and .d4iot_conf files into .auth, .conf, .auth_d4iot, and .d4iot_conf.
- Removed token_cache.bin.
- Added longer timeouts for selenium.
- Added validationkey pull as part of the regular M365 authentication flow.

### Fixed
- Added a section in the Installing section of the readme for Ubuntu 22.04 users running into wxpython issues.

## [1.0.0] - The goose is loose - 2023-03-23
### Added
- Goose is released

### Changed


### Fixed
