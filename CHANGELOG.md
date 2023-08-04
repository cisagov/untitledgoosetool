# Untitled Goose Tool Change Log

All notable changes to this project will be documented in this file.

## [1.2.5] - The goose is loose - 2023-08-04
### Added

### Changed
- Updated `cryptography` to 41.0.3 based on dependabot.

### Fixed
- Incorporated fix for function `helper_multiple_object` when parent object contains a `/`
- Updated authentication fix for graze.py and messagetrace.py

## [1.2.4] - The goose is loose - 2023-07-27
### Added

### Changed
- Updated and pinned `MSAL` dependencies.

### Fixed
- Updated `validationkey` logic for m365 authentication.
- Updated `MSAL` calls to align with the `MSAL` 1.23.0 change.

## [1.2.3] - The goose is loose - 2023-07-20
### Added

### Changed
- Updated `cryptography` and `aiohttp` based on dependabot.
- Updated SBOM files.

### Fixed

## [1.2.2] - The goose is loose - 2023-07-17
### Added
- Better catches for when password for the account needs to be updated, when a conditional access policy blocks user account access, or when the user account is flagged for risky actions.
- Added catch for empty `.conf` fields, will allow more graceful exiting. 

### Changed
- Updated and pinned `aiohttp`, `colored`, `cryptography`, and `selenium` dependencies and updated Python version to 3.10.11.
- Pinned 3.1.0 version of ExchangeOnlineManagement PowerShell module.
- Improved logic for grabbing `validationkey` from requests.

### Fixed
- Fixed MFA logic for messagetrace.py.
- Fixed data dumper logic, they will only run if something in their section is set to `True`.

## [1.2.1] - The goose is loose - 2023-06-06
### Added
- Implemented new tables to be pulled from MDE.
- Added two SBOM files.

### Changed
- Updated readme with cloud-only account requirement.
- Better logging for _no_results.json.

### Fixed
- Fixed Azure government calls.
- Fixed minor debug logging issues.
- Fixed the AttributeError encountered during AzureAD calls.

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
