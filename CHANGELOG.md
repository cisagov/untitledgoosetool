# Untitled Goose Tool Change Log

All notable changes to this project will be documented in this file.

## [2.2.0] - AutoHonk - 2026-09-01
### Added
- Better task naming for logging.
- Microsoft Graph role `ThreatHunting.Read.All`.
- Log Analytics API role `Data.Read`.
- Support for dumping Log Analytics Workspace data.
- More documentation.
- `autohonk` for automated authentication.
- Additional configuration options for UAL task tuning and optional extra time fields.
- Unified Audit Log filter variables in the `[variables]` section of `.conf`:
  - `ual_operations` for filtering UAL requests by operation name.
  - `ual_userids` for filtering saved UAL results by user ID.
  - `ual_clientip` for filtering saved UAL results by client IP address.

### Changed
- Updated required package versions.
- Updated `Create_SP.ps1` to streamline setup by:
  - removing the Cloud Shell prompt,
  - adding GCC High support,
  - reusing an existing role group with the app name when present.
- `goosey conf` now prompts for the client secret instead of requiring it as an argument.
- Renamed `azuread` references to `entraid`.
- Removed version and author metadata from files.
- Improved UAL pulling efficiency.
- Unified Audit Log collection now supports configurable filtering behavior through `.conf`.
- `ual_operations` is passed to the `Search-UnifiedAuditLog` API as the `Operations` parameter when set.
- `ual_userids` and `ual_clientip` are applied client-side after retrieval.
- When multiple UAL filters are configured, records must match all configured filters to be saved.
- MDE query mode supports `table` or `machine` collection strategies for large tenant performance tuning.
- Improved async handling for Azure dumpers.
- Improved logging for Python 3.12 and updated the Docker image.
- Better support for GCC and GCC High.

### Fixed
- Fixed errors in `Create_SP.ps1`.
- Resolved `goosey honk` dumper argument issues such as `--entraid`.
- Fixed issues in D4IoT dumpers.
- Fixed configuration collection issues, especially for security contacts.
- Fixed endless pulling for sign-in logs when `endtime` was not specified.
- Fixed async issues in Azure dumpers.
- Fixed missing save state for Azure Activity Log.

### Notes
- `ual_operations`, `ual_userids`, and `ual_clientip` may require separate UAL pulls depending on the collection goal.
- Running duplicate UAL timeframes with different filters may require clearing saved bounds and state files before rerunning.
- Because `ual_userids` and `ual_clientip` are applied after retrieval, API-side result counts and threshold behavior still reflect the full unfiltered response.

## [2.1.0] - Enter the honk - 2024-02-19
### Added
- Added support for python 3.13

## [2.0.4] - Enter the honk - 2024-01-28
### Changed
- Create_SP.ps1 script no longer prompts for cloudshell
- Create_SP.ps1 script supports gcc high
- goosey conf command now prompts for the client secret instead of having it provided as an argument

### Fixed
- Support for gcc and gcc high
- Fixed errors in install script Create_SP.ps1

## [2.0.3] - Enter the honk - 2024-09-23
### Added
- Better task naming for logging
- Added Microsoft Graph role ThreatHunting.Read.All
- Added Log Analytics API role Data.Read
- Added dumping for Log Analytics Workspace

### Changed
- Updated versions of required packages
- Create_SP.ps1 script will find existing an existing role group with the app name instead of erroring

### Fixed
- Resolved issue with dumper cmd arguments for honk command not working (e.g. goosey honk --entraid)
- Issue identified in d4iot dumpers

## [2.0.2] - Enter the honk - 2024-08-21
### Added
- Better task naming for logging

### Changed
- Updated versions of required packages

### Fixed
- Resolved some errors for config collection. Specifically relating to the security contacts collection


## [2.0.1] - Enter the honk - 2024-07-31
### Added
- More Documentation

### Changed
- Changed all azuread to entraid
- Removed version and author information from every file

### Fixed
- Endless pulling issue for sign in logs when endtime wasn't specified

## [2.0.0] - Enter the honk - 2024-05-08
### Added
- autohonk. No more manual authentication
- Variables added to the conf to modify ual tasks running as well as optional extra time field

### Changed
- more efficient ual pulling. Lots of improvements that led to an 800% speed up.
- fixed asynchronous issue with azure dumpers
- Better Logging for python3.12. Changed the docker image to use that as well

### Fixed
- Asynchronous issues with azure dumpers
- No save state for azure activity log

## [2.0.0-b] - Enter the honk - 2024-02-08
### Added
- Powershell script for tying service principal to exchange online
- App only authentication
- `goosey conf` command to generate the conf. Includes comments for each field
- Variables added to the conf to modify thresholds and modes during goosey honk

### Changed
- Ual changed endpoints due to previous endpoint deprecation. New endpoint uses app auth tied to exchange online. No user tokens required for anything anymore.
- Mde improvements and mode added to choose between table mode and machine.
- Cli framework switched to fire instead of argparse
- Graze is gone. Due to ual change
- GUI is gone due to not being supported.
- Powershell dumper for m365 switched to python implementation
- delegated auth pull removed. Permissions too strong
- auth no longer saves unencrypted creds/tokens to disk in secure mode at any point
- Summarized configuration pulls in AzureAD and Azure.

### Fixed
- duplication in ual logs. Duplicates returned are now deduped before saving

## [1.2.6] - The goose is loose - 2023-09-15
### Added
- Delegated auth pull for featureRolloutPolicies
- Made goose proxy aware

### Changed
- Consolidated auth code and enabled secure by default
- Made graze faster

### Fixed
- Fixed AzureAD activity log dumper bug that failed if there were multiple subscriptions

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
