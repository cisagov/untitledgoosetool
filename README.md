#

<div align="center">

<h3 align="center">Untitled Goose Tool</h3>

---
<p align="center"> The Goose is loose.
    <br>
</p>

</div>

## Table of Contents
- [About](#about)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Requirements](#requirements)
  - [Installing](#installing)
- [Usage](#usage)
  - [Config](#config)
  - [GUI](#gui)
  - [Auth](#auth)
  - [Csv](#csv)
  - [Honk](#honk)
  - [Messagetrace](#messagetrace)
  - [Recommended Default Workflow](#recommended-default-workflow)
  - [Recommended Workflow for UAL Call with Time Bounds](#recommended-workflow-for-ual-call-with-time-bounds)
  - [Considerations](#considerations)
- [Known Issues](#known-issues)
- [Acknowledgements](#acknowledgements)
- [Contributing](#contributing)
- [License](#license)
- [Legal Disclaimer](#legal-disclaimer) 

## About

Untitled Goose Tool is a robust and flexible hunt and incident response tool that adds novel authentication and data gathering methods in order to run a full investigation against a customer’s Microsoft Entra ID, Azure, and M365 environments. Untitled Goose Tool gathers additional telemetry from Microsoft Defender for Endpoint (MDE) and Defender for Internet of Things (IoT) (D4IoT).

This tool was designed to assist incident response teams by exporting cloud artifacts after an incident for environments that aren't ingesting logs into a Security Information and Events Management (SIEM) or other long term solution for logs.

For more guidance on how to use Untitled Goose Tool, please see: [Untitled Goose Tool Fact Sheet](https://www.cisa.gov/resources-tools/resources/untitled-goose-tool-fact-sheet)

## Getting Started

### Prerequisites
Python >= 3.9 is required to run Untitled Goose Tool with Python. Python 3.12 is highly recommended as it results in better logging.

On a Windows machine, you will need to make sure to have the Microsoft Visual C++ redistributable package (14.x) installed prior to running the tool.

It's also recommended to run Untitled Goose Tool within a virtual environment.

#### Mac OSX
```sh
pip3 install virtualenv
virtualenv -p python3 .venv
source .venv/bin/activate
```

#### Linux
```sh
# You may need to run sudo apt-get install python3-venv first
python3 -m venv .venv
source .venv/bin/activate
```

#### Windows
```console
# You can also use py -3 -m venv .venv
python -m venv .venv
.venv\Scripts\activate
```

### Requirements
The following EntraID/M365 permissions are required to run Untitled Goose Tool, and provide it read-only access to the tenant.

Please note: The user account should be a cloud-only account (not sync'd to the on-premise environment), this will ensure that the login process stays the same across environments for the tool.

A cloud-only user account and associated EXO service principal with the following permissions:

Exchange Online Admin Center
```
- View-Only Audit Logs
- View-Only Configuration 
- View-Only Recipients
- User Options
```

A service principal with the following permissions:

API Permissions
```
Microsoft Threat Protection:
- AdvancedHunting.Read.All (Application)

WindowsDefenderATP:
- AdvancedQuery.Read.All (Application)
- Alert.Read.All (Application)
- Library.Manage (Application)
- Machine.Read.All (Application)
- SecurityRecommendation.Read.All (Application)
- Software.Read.All (Application)
- Ti.ReadWrite (Application)
- Vulnerability.Read.All (Application)

Microsoft Graph:
- APIConnectors.Read.All (Application)
- AuditLog.Read.All (Application)
- ConsentRequest.Read.All (Application)
- Directory.Read.All (Application)
- Domain.Read.All (Application)
- IdentityProvider.Read.All (Application)
- IdentityRiskEvent.Read.All (Application)
- IdentityRiskyServicePrincipal.Read.All (Application)
- IdentityRiskyUser.Read.All (Application)
- MailboxSettings.Read (Application)
- Policy.Read.All (Application)
- Policy.Read.PermissionGrant (Application)
- Reports.Read.All (Application)
- RoleManagement.Read.All (Application)
- SecurityActions.Read.All (Application)
- SecurityAlert.Read.All (Application)
- SecurityEvents.Read.All (Application)
- UserAuthenticationMethod.Read.All (Application)

Office 365 Exchange Online
- Exchange.ManageAsApp
```

Azure Subscription IAM Roles
```
- Reader
- Storage Blob Data Reader
- Storage Queue Data Reader
```

Make sure to enable "Allow public client flows" for the service principal.

We have a [setup powershell script](scripts/Create_SP.ps1) to setup a service principal with the needed permissions. Additionally the association of the Azure Service Principal with m365 can only be done via powershell currently and is needed for some of the m365 log collection.

Below is an example of running the script which will output the `goosey conf` command you need to run to build the config files with the proper information

```powershell
PS > Write-Host "Creating a new Goose Application and Users"
PS > ./Create_SP.ps1 -AppName GooseApp -Create
```

Additionally the script can delete the Application when you are done using it
```powershell
PS > Write-Host "Creating a new Goose Application and Users"
PS > ./Create_SP.ps1 -AppName GooseApp -Delete
```

### Installing
To install, clone the repository and then do a pip install:

#### Regular Install

```sh
git clone https://github.com/cisagov/untitledgoosetool.git
cd untitledgoosetool
python3 -m pip install . 
```

#### Docker

```sh
docker build . -t goosey
docker run -it -v $PWD:/workdir goosey goosey honk --debug
```


## Usage
### Config

Untitled Goose Tool requires authentication parameters and configuration. To automatically build the configuration file, run the following after installation.

```sh
$ goosey conf
```

A version of this command will be generated when the powershell installation script is run to create/setup the service principal. Below is an example with fake parameter values

```sh
$ goosey conf --config_tenant=5fd146ad-8b31-4afa-a72f-6f71df5c7173 --config_subscriptionid=all --auth_appid=24fd6377-79e0-445d-838b-3eaa60d3ca21 --auth_clientsecret=9gh8Q~U7Sd.TRNad5Qpd_GL_UM1slEPJTOLyGt-_ 
```

After this, `.auth`, `.conf`, `.auth_d4iot`, and `.d4iot_conf` files should be placed in your current directory. These files are used by Untitled Goose Tool. Unless this was generated with the above parameters, you should fill out the top section `[auth]` so that Untitled Goose Tool can properly auth to the appropriate resources. However, if you do not feel comfortable about entering your credentials into a file, you can opt to delete the `.auth` and/or `.auth_d4iot` and be prompted by the tool for credentials via console instead.

The barebones auth looks like:

```
[auth]
# The username of your account. ex: AAD_upn@example.onmicrosoft.com
username=
# The password of your account. ex: AAD_password
password=
# The application ID of your service principal
appid=
# The client secret value of your service principal (not the secret ID)
clientsecret=
```

The barebones config looks like:

```
[config]
# The tenant ID of your AAD tenant
tenant=
# If you have a GCC High tenant
us_government=False
# If you have a GCC tenant with MDE
mde_gcc=False
# If you have a GCC High tenant with MDE
mde_gcc_high=False
# If your M365 tenant is a government tenant
exo_us_government=False
# If you want to check all of your Azure subscriptions, set this to All, otherwise enter your Azure subscription ID. For multiple IDs, separate it with commas, no spaces
subscriptionid=All

[filters]
# Format should be YYYY-MM-DD. If not set will default to the earliest date for log retention
date_start=
# Format should be YYYY-MM-DD. Will default to the present day
date_end=

[variables]
# Threshold used for ual API requests. Specifies the maximum results pulled per session. Can be between 100 - 50000. The api is optimized to return results faster the larger the threshold, but the whole session has to be repeated if an error occurs as the results are not returned sorted. We recommend 5000 as the threshold, but this can be toggled with
ual_threshold=5000
# Maximum number of ual coroutines/tasks to have running asynchronously. Minimum value is 1.
max_ual_tasks=5
# Start date for an extra time frame for ual to search. Reason for this is because ual takes the longest to pull and while you don't want the oldest data to roll off, you may want to look at another timeframe and do not want to wait for ual to get there and pull the logs. Format should be YYY-MM-DD
ual_extra_start=
# End date for an extra time frame for ual to search. Reason for this is because ual takes the longest to pull and while you don't want the oldest data to roll off, you may want to look at another timeframe and do not want to wait for ual to get there and pull the logs. Format should be YYY-MM-DD
ual_extra_end=
# Threshold for how many logs to pull per query. Usually want to try to max this out as KQL queries are rate limited.
mde_threshold=10000
# can be either 'table' or 'machine'. 'table' will pull directly from the mde tables without filtering. While 'machine' will filter by 'machine' with large tenants 'machine' will likely be prefered as time bounding on the entire table will likely cause issues.
mde_query_mode=table

[azure]
# Dumps activity log from azure
activity_log=False
# Returns all azure subscriptions
all_azure_subscriptions=False
# Dump insights bastion audit logs
bastion_logs=False
# Dump Azure configuration information
configs=False
# Dump D4IOT portal configs
d4iot_portal_configs=False
# Dump D4IOT portal pcaps from alerts
d4iot_portal_pcap=False
# Dump insights audit events for key_vault
key_vault_log=False
# Dump insights network security group flow events
nsg_flow_logs=False

[entraid]
# Dumps Entra ID Audit logs
entraid_audit=False
# Dumps Entra ID provisioning logs
entraid_provisioning=False
# Dumps Entra ID configuration files
configs=False
# Dumps risk detections from identity protection. Requires a minimum of Microsoft Entra ID P1 license and Microsoft Entra Workload ID premium license for full results.
risk_detections=False
# Dumps risky users and service principal information. Requires a minimum of Microsoft Entra ID P2 license and Microsoft Entra Workload ID premium license for full results.
risky_objects=False
# Dump security actions, alerts, and scores
security=False
# Dump interactive (adfs) sign in logs
signins_adfs=False
# Dump managed identity (msi) sign in logs
signins_msi=False
# Dump non-interactive (rt) sign in logs
signins_rt=False
# Dump service principal (sp) signin logs
signins_sp=False

[m365]
# Get Exchange discovery information
ediscovery_info=False
# Get all of the applications installed for the organization
exo_addins=False
# Get EXO config information
exo_config_info=False
# Dumps Exchange Online Role Group and Role Group Members information.
exo_groups=False
# Get all the messageRule objects defined for all users' inboxes
exo_inboxrules=False
# Dumps Exchange Online Mailbox Information
exo_mailbox=False
# Get information on m365 mobile devices
exo_mobile_devices=False
# Dumps UAL for last year using Search-UnifiedAuditLog api. Previous ual api is currently deprecated.
ual=False

[mde]
# Dumps the results from incidents and alerts.
advanced_hunting_alerts_incidents=False
# Dumps the results from advanced hunting queries.
advanced_hunting_query=False
# Dumps the results from advanced hunting API queries.
advanced_identity_hunting_query=False
# Dump alerts
alerts=False
# Dump indicators
indicators=False
# Dump investigations
investigations=False
# Dump library files
library_files=False
# Dump known machine vulnerabilities
machine_vulns=False
# Dump machines with mde
machines=False
# Dump mde recommendations
recommendations=False
# Dump known installed software
software=False
```

The barebones D4IoT auth looks like:
```
[auth]
# Username for your D4IoT sensor login page
username=
# Password for your D4IoT sensor login page
password=
# Enter your D4IoT sensor API token
sensor_token=
# Enter your D4IoT management console API token
mgmt_token=
```

The D4IoT config looks like:
```
[config]
# Enter your D4IoT sensor IP
d4iot_sensor_ip=
# Enter your D4IoT management console IP
d4iot_mgmt_ip=

[d4iot]
# Dump management alerts
mgmt_alerts=False
# Dump management devices
mgmt_devices=False
# Dump management sensor pcap captured
mgmt_pcap=False
# Dump management sensor information
mgmt_sensor_info=False
# Dump sensor alerts
sensor_alerts=False
# Collect all device connections
sensor_device_connections=False
# Dummp sensor device known cves
sensor_device_cves=False
# Dump sensor device known vulnerabilities
sensor_device_vuln=False
# Dump sensor devices
sensor_devices=False
# Dump sensor events
sensor_events=False
# Dump sensor operation vulnerabilities
sensor_operational_vuln=False
# Dump sensor pcap
sensor_pcap=False
# Dump sensor security vulnerabilities
sensor_security_vuln=False
```

To enable specific pulls, you can change occurrences of `False` to `True` (case insensitive).

### Auth

```sh
$ goosey auth --help
NAME
    goosey auth - Untitled Goose Tool Authentication

SYNOPSIS
    goosey auth <flags>

DESCRIPTION
    Untitled Goose Tool Authentication

FLAGS
    --authfile=AUTHFILE
        Default: '.ugt_auth'
        File to store the authentication tokens and cookies
    --d4iot_authfile=D4IOT_AUTHFILE
        Default: '.d4iot_auth'
        File to store the authentication cookies for D4IoT
    -c, --config=CONFIG
        Default: '.conf'
        Path to config file
    --auth=AUTH
        Default: '.auth'
        File to store the credentials used for authentication
    --d4iot_auth=D4IOT_AUTH
        Default: '.auth_d4iot'
        File to store the D4IoT credentials used for authentication
    --d4iot_config=D4IOT_CONFIG
        Default: '.d4iot_conf'
    -r, --revoke=REVOKE
        Default: False
        Revoke sessions for user with authentication tokens and cookies
    --interactive=INTERACTIVE
        Default: False
        Interactive mode for Selenium. Default to headless
    --debug=DEBUG
        Default: False
        Enable debug logging
    --d4iot=D4IOT
        Default: False
        Run the authentication portion for d4iot
    --insecure=INSECURE
        Default: False
        Disable secure authentication handling (file encryption)
    -u, --user_auth=USER_AUTH
        Default: False
        Authenticate with the user credentials and collect the session tokens
```

Run with defaults. By default it will encrypt the credentials/tokens with a prompted password. If the fields are not defined in the config then it will prompt for those as well:
```sh
$ goosey auth
```

Run with debug and insecure authentication handling enabled:
```sh
$ goosey auth --debug --insecure
```

### Csv

```sh
$ goosey csv --help
NAME
    goosey csv - Create csv files mapping GUIDs to text

SYNOPSIS
    goosey csv <flags>

DESCRIPTION
    Create csv files mapping GUIDs to text

FLAGS
    -o, --output_dir=OUTPUT_DIR
        Default: 'output/entraid/'
        The directory where the goose files are located
    -r, --result_dir=RESULT_DIR
        Default: 'output/csvs/'
        Directory for storing the results
    -d, --debug=DEBUG
        Default: False
        Enable debug logging
```

Run with defaults:
```sh
$ goosey csv
```

### Honk

```sh
$ goosey honk --help
NAME
    goosey honk - Untitled Goose Tool Information Gathering

SYNOPSIS
    goosey honk <flags>

DESCRIPTION
    Untitled Goose Tool Information Gathering

FLAGS
    --authfile=AUTHFILE
        Default: '.ugt_auth'
        File to store the authentication tokens and cookies
    -c, --config=CONFIG
        Default: '.conf'
        Path to config file
    --auth=AUTH
        Default: '.auth'
        File to store the credentials used for authentication
    -o, --output_dir=OUTPUT_DIR
        Default: 'output'
        Directory for storing the results
    -r, --reports_dir=REPORTS_DIR
        Default: 'reports'
        Directory for storing debugging/informational logs
    --debug=DEBUG
        Default: False
        Enable debug logging
    --dry_run=DRY_RUN
        Default: False
        Dry run (do not do any API calls)
    --azure=AZURE
        Default: False
        Set all of the Azure calls to true
    --entraid=ENTRAID
        Default: False
        Set all of the Entra ID calls to true
    --m365=M365
        Default: False
        Set all of the M365 calls to true
    --mde=MDE
        Default: False
        Set all of the MDE calls to true
```

Run with default options:
```sh
$ goosey honk
```

Run with debug logging enabled, output to directory `my_outputs`, and enable all Azure calls:
```sh
$ goosey honk --debug --output-dir my_outputs --azure
```

### Autohonk

```sh
$ goosey autohonk --help
NAME
    goosey autohonk - Untitled Goose Tool Information Gathering. With auto authentication! This will never stop until you tell it to.

SYNOPSIS
    goosey autohonk <flags>

DESCRIPTION
    Untitled Goose Tool Information Gathering. With auto authentication! This will never stop until you tell it to.

FLAGS
    --authfile=AUTHFILE
        Default: '.ugt_auth'
        File to store the authentication tokens and cookies
    -c, --config=CONFIG
        Default: '.conf'
        Path to config file
    --auth=AUTH
        Default: '.auth'
        File to store the credentials used for authentication
    -o, --output_dir=OUTPUT_DIR
        Default: 'output'
        Directory for storing the results
    -r, --reports_dir=REPORTS_DIR
        Default: 'reports'
        Directory for storing debugging/informational logs
    -d, --debug=DEBUG
        Default: False
        Enable debug logging
    --azure=AZURE
        Default: False
        Set all of the Azure calls to true
    --entraid=ENTRAID
        Default: False
        Set all of the Entra ID calls to true
    --m365=M365
        Default: False
        Set all of the M365 calls to true
    --mde=MDE
        Default: False
        Set all of the MDE calls to true
    -i, --insecure=INSECURE
        Default: False
        Disable secure authentication handling (file encryption)
```


### Recommended Default Workflow

1. Install the tool `pip install .`
2. (Optional) Run the [setup powershell script](scripts/Create_SP.ps1) to setup the service principal for your tenant
3. Use the outputed `goosey conf` command. Or just run it with no parameters
4. Fill out the .auth file with your credentials (if you didn't use the output from the powershell script)
5. Fill out the configuration information and set wanted calls in the .conf file to `True`.
6. Run `goosey auth` with desired parameters.
7. Run `goosey honk` with desired parameters.
8. Instead of steps 6-7 run `goosey autohonk` with desired parameters

### Recommended Workflow for UAL Call

1. Steps 1-4 above
2. Open the .conf file and set `ual` under the `m365` section to `True`.
3. Run `goosey auth` with desired parameters.
4. Run `goosey honk` with desired parameters.
5. Instead of steps 3-4 run `goosey autohonk` with desired parameters

### Considerations

1. We recommend running the [setup powershell script](scripts/Create_SP.ps1) or filling out the .conf first
2. Filling out the .auth and/or .auth_d4iot is now optional.
3. Always run `goosey auth` before running `goosey honk` or `goosey d4iot`. `goosey autohonk` will perform authentication on it's own.

### Special Use Cases

#### Behind a proxy

The tool should work behind a proxy. As long as the appropriate environment variables for the cli are set
```
https_proxy=<proxy_url>
http_proxy=<proxy_url>
```

### Known Issues

1. Having `%` in the password:

    **Solution:** Make sure to escape `%` in the password with `%%`.

2. Error when attempting to `pip install .` when you are on Mac:

    ```sh
    ModuleNotFoundError: No module named 'certifi'
    ```
    **Solution:** Go to your applications folder, find your python version folder, and double click on the file "Install Certificates.command" inside the python folder to install the certificate.

3. Why does Untitled Goose Tool return two results for Exchange Online inbox rules and Exchange Online mailbox permissions?

    **Solution:** Both the API and PowerShell calls are robust and show different information, so we decided to keep both.

4. Error after running certain Azure Security Center calls:

    Azure Compliance Results:
    ```sh
    Error: (MissingSubscription) The request did not have a subscription or a valid tenant level resource provider.
    Code: MissingSubscription
    Message: The request did not have a subscription or a valid tenant level resource provider.
    ```

    Azure Information Protection Policies:
    ```sh
    Error: Operation returned an invalid status 'Not Found'
    ```

    Azure Assessments:
    ```sh
    Discriminator source is absent or null, use base class ResourceDetails.
    ```

    Azure SubAssessments:
    ```sh
    Subtype value GeneralVulnerability has no mapping, use base class AdditionalData.
    Subtype value SqlVirtualMachineVulnerability has no mapping, use base class AdditionalData.
    ```

    **Solution:** These messages aren't issues. Azure compliance result call will still complete. The Azure information protection policy call is not a critical error. The Azure assessments call spams the console with one line warning: "Discriminator source is absent or null, use base class ResourceDetails" and will complete without an issue (besides the console spam). The Azure subassessments call spams the console with one line warning: "Subtype value GeneralVulnerability has no mapping, use base class AdditionalData." or "Subtype value SqlVirtualMachineVulnerability has no mapping, use base class AdditionalData." and will complete without an issue (besides the console spam).

5. Excessive amount of 429 errors during `goosey honk`

    **Solution:** Untitled Goose Tool will quickly encounter the Graph API limitations of a tenant; this is a limitation that Microsoft has on Graph API calls. 


## Acknowledgements

- Claire Casalnova
- Jordan Eberst
- Nicholas Kantor
- Wellington Lee
- Victoria Wallace

## Contributing

We welcome contributions!  Please see [here](CONTRIBUTING.md) for details.

## License

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.

## Legal Disclaimer

NOTICE

This software package (“software” or “code”) was created by the United States Government and is not subject to copyright within the United States. All other rights are reserved. You may use, modify, or redistribute the code in any manner. However, you may not subsequently copyright the code as it is distributed. The United States Government makes no claim of copyright on the changes you effect, nor will it restrict your distribution of bona fide changes to the software. If you decide to update or redistribute the code, please include this notice with the code. Where relevant, we ask that you credit the Cybersecurity and Infrastructure Security Agency with the following statement: “Original code developed by the Cybersecurity and Infrastructure Security Agency (CISA), U.S. Department of Homeland Security.”

USE THIS SOFTWARE AT YOUR OWN RISK. THIS SOFTWARE COMES WITH NO WARRANTY, EITHER EXPRESS OR IMPLIED. THE UNITED STATES GOVERNMENT ASSUMES NO LIABILITY FOR THE USE OR MISUSE OF THIS SOFTWARE OR ITS DERIVATIVES.

THIS SOFTWARE IS OFFERED “AS-IS.” THE UNITED STATES GOVERNMENT WILL NOT INSTALL, REMOVE, OPERATE OR SUPPORT THIS SOFTWARE AT YOUR REQUEST. IF YOU ARE UNSURE OF HOW THIS SOFTWARE WILL INTERACT WITH YOUR SYSTEM, DO NOT USE IT.
