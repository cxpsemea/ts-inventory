# Checkmarx Inventory Tool

Application to inventory (extract) relevant contents from a Checkmarx product instance or tenant.

### Objective

Extract and identify all the relevant system and object contents from a Checkmarx product instance.
Assist on migration planning, especially for SAST to CXONE migrations, by identify potential issues, collisions, and blockers, that may require any type of correction, handling, or preparation.

### Coverage

The tool can extract data from SAST, CXONE, or SCA instances.

## Index

- [Invocation commands, options, and arguments](#invocation-commands-options-and-arguments)
- [Examples (command line)](#examples-command-line)
- [Execution output](#execution-output)
- [Required Permissions](#required-permissions)
- [Notice](#notice)

## Invocation commands, options, and arguments

Use **cxinventory --help** for the available arguments, described in the table down in this document.
All arguments may passed in command-line, as environment variables, or defined in a config.yaml file.
The invocation, to extract inventory from SAST, with ALL options is:

**cxinventory sast --sast.url https://sast.domain.net --sast.username user_name --sast.password user_pass --options.detailed-users --options.include-repos**

All the below can be used from command line, in the config.yaml, and in environment variables prefixed with "*CXTOOL_*"

#### General commands, to indicate the target system type (SAST, CXONE, or SCA). Only one can be selected.

|Command|Description|
|---|---|
|sast|Command to inventory a SAST environment. This is the default and will be used if no command is selected.|
|cxone|Command to inventory a CXONE tenant.|
|sca|Command to inventory an SCA tenant.|

#### Execution options. 

|Argument|Description|
|---|---|
|--options.no-iam|If present, access control data will NOT be collected, such as users, teams, roles, and IdP.|
|--options.detailed-users|If present, collect complete users list. By default, the users are not collected.|
|--options.include-repos|If present, include reporitory/branch information in the projects. Not collected by default.|
|--options.no-scans|If present, exclude scan information from projects. Included by default.|
|--options.no-triages|If present, exclude triage counts information from projects. Included by default.|
|--options.projects-filter|To select which projects to include in the extraction. All projects included by default.|

The projects filter can be set as:
- A single project ID, like ***--options.projects-filter 1*** (SAST) or ***--options.projects-filter 5ba5b65-4171-4636-a076-74f2576c1eb3*** (SCA or CXONE)
- An list of project IDs, like ***--options.projects-filter 1,2,3*** (SAST) or ***--options.projects-filter 95ba5b65-4171-4636-a076-74f2576c1eb3,1bb43b88-4a7b-4cba-b7b7-ae730678999a*** (SCA or CXONE)
- A file containing a list of project IDs, like ***--options.projects-filter "@file(C:\data\filter.txt)"***
- All projects below an ID, exclusive, like ***--options.projects-filter <2*** (SAST only)
- All projects above an ID, exclusive, like ***--options.projects-filter >2*** (SAST only)
- All projects below an ID, inclusive, like ***--options.projects-filter <=2*** (SAST only)
- All projects above an ID, inclusive, like ***--options.projects-filter >=2*** (SAST only)

#### Optional arguments.

|Argument|Description|
|---|---|
|--help|To display and help screen.|
|--debug|To log debug information.|

#### Connection parameters, to use the one associated to the system being used (SAST, CXONE, or SCA)

|Parameter|Description|
|---|---|
|--sast.url|SAST url (i.e.: https://portal.checkmarx.net).|
|--sast.username|SAST user name.|
|--sast.password|SAST password.|
|--sast.insecure|Set to "true" to bypass SSL/TLS validation. Defaults to false.|
|--sast.proxy_url|SAST outbound proxy url, if a proxy is used to connect.|
|--sast.proxy_username|SAST proxy user name, if the proxy requires authentication (basic only).|
|--sast.proxy_password|SAST proxy password, if the proxy requires authentication (basic only).|
|--cxone.url|CXONE portal url (i.e.: https://eu.ast.checkmarx.net).|
|--cxone.iamurl|CXONE access management url (i.e.: https://eu.iam.checkmarx.net).|
|--cxone.tenant|CXONE tenant name.|
|--cxone.apikey|CXONE api key or client secret if a non "ast-app" client id is used.|
|--cxone.clientid|CXONE client id, defaults to "*ast-app*".|
|--cxone.granttype|CXONE grant type, defaults to "*refresh_token*"|
|--cxone.insecure|Set to "true" to bypass SSL/TLS validation. Defaults to false.|
|--cxone.proxy_url|CXONE outbound proxy url, if a proxy is used to connect.|
|--cxone.proxy_username|CXONE proxy user name, if the proxy requires authentication (basic only).|
|--cxone.proxy_password|CXONE proxy password, if the proxy requires authentication (basic only).|
|--sca.url|SCA portal url (i.e.: https://api-sca.checkmarx.net).|
|--sca.iamurl|SCA access management url (i.e.: https://platform.checkmarx.net).|
|--sca.tenant|SCA tenant name.|
|--sca.username|SCA user name.|
|--sca.password|SCA password.|
|--sca.insecure|Set to "true" to bypass SSL/TLS validation. Defaults to false.|
|--sca.proxy_url|SCA outbound proxy url, if a proxy is used to connect.|
|--sca.proxy_username|SCA proxy user name, if the proxy requires authentication (basic only).|
|--sca.proxy_password|SCA proxy password, if the proxy requires authentication (basic only).|

## Examples (command line)

Extract from SAST:
- Default: **`cxinventory sast --sast.url https://portal.checmarx.net --sast.username username --sast.password password`**
- Complete: **`cxinventory sast --sast.url https://portal.checmarx.net --sast.username username --sast.password password --options.detailed-users --options.include-repos`**

Extract from CXONE:
- Default with api-key: **`cxinventory cxone --cxone.url https://eu.ast.checkmarx.net --cxone.acl https://eu.iam.checkmarx.net --cxone.tenant tenant_name --cxone.apikey api_key`**
- Complete with api-key: **`cxinventory cxone --cxone.url https://eu.ast.checkmarx.net --cxone.acl https://eu.iam.checkmarx.net --cxone.tenant tenant_name --cxone.apikey api_key --options.detailed-users --options.include-repos`**
- Default with oauth: **`cxinventory cxone --cxone.url https://eu.ast.checkmarx.net --cxone.acl https://eu.iam.checkmarx.net --cxone.tenant tenant_name --cxone.clientid client_id --cxone.apikey client_secret`**
- Complete with oauth: **`cxinventory cxone --cxone.url https://eu.ast.checkmarx.net --cxone.acl https://eu.iam.checkmarx.net --cxone.tenant tenant_name --cxone.clientid client_id --cxone.apikey client_secret --options.detailed-users --options.include-repos`**

Extract from SCA:
- Default: **`cxinventory sca --sca.url https://api-sca.checkmarx.net --sca.acl https://platform.checkmarx.net --sca.tenant tenant_name --sca.username username --sca.password password`**
- Complete: **`cxinventory sca --sca.url https://api-sca.checkmarx.net --sca.acl https://platform.checkmarx.net --sca.tenant tenant_name --sca.username username --sca.password password --options.detailed-users`**

## Execution output

Up to 10 CSV files are generated with the relevant content, with the names prefixed with the environment type, with the following detail:

|CSV File|Platforms|Description|
|---|---|---|
|*_inventorysummary.csv|SAST, CXONE, SCA|Summary with key items.|
|*_inventoryconfigurations.csv|SAST, CXONE, SCA|System information and configuration items.|
|*_inventoryusers.csv|SAST, CXONE, SCA|List of users, if options.detailed-users is selected.|
|*_inventoryteams.csv|SAST, SCA|List of teams.|
|*_inventorygroups.csv|CXONE|List of groups.|
|*_inventoryroles.csv|SAST, CXONE, SCA|List of roles.|
|*_inventoryqueries.csv|SAST, CXONE|Custom queries.|
|*_inventorypresets.csv|SAST, CXONE|Existing presets.|
|*_inventorypresetqueries.csv|SAST, CXONE|Queries associated with presets.|
|*_inventorycustomcategories.csv|SAST|Existing query categories.|
|*_inventoryapplications.csv|CXONE|Existing applications.|
|*_inventoryprojects.csv|SAST, CXONE, SCA|List of existing projects.|

## Required permissions

The authorizations required for execution in each of the platforms are:

#### For SAST
Recommended roles: "SAST Admin" and "Access Control Manager", or the minimum permissions:
|Permissions|Description|
|---|---|
|manage-users and/or manage-teams|Required to retrieve users and teams. If missing data will not be collected.|
|manage-authentication-providers|Required to retrieve external IdP configurations. If missing data will not be collected.|
|manage-roles|Required to retrieve roles. If missing data will not be collected.|
|manage-engine-servers|Required to retrieve engine configurations. If missing data will not be collected.|
|manage-custom-fields|Required to retrieve custom fields. If missing data will not be collected.|
|manage-issue-tracking-systems|Required to retrieve issue tracking (JIRA) configurations. If missing data will not be collected.|
|manage-pre-post-scan-actions|Required to retrieve pre and post scan actions. If missing data will not be collected.|
|manage-system-settings|Required to retrieve system settings. If missing data will not be collected.|
|save-project or update-project|Required to retrieve project scan configurations. If missing data will not be collected.|
|view-results|Required to retrieve scan and scan results data. ***Mandatory***, if missing the inventory will not run.|
|use-odata|Required to retrieve project inventory data. ***Mandatory***, if missing the inventory will not run.|

#### For CXONE
Recommended roles: "ast-viewer" and "iam-admin", or the minimum permissions:
|Permissions|Description|
|---|---|
|manage-users and/or manage-teams|Required to retrieve users, teams, and roles. If missing data will not be collected.|
|iam-admin or view-identity-providers|Required to retrieve external IdP configurations. If missing data will not be collected.|
|view-tenant-params|Required to retrieve tenant configurations. If missing data will not be collected.|
|view-queries|Required to retrieve queries. If missing data will not be collected.|
|view-scans|Required to retrieve scans. If missing data will not be collected.|
|view-results|Required to retrieve scans results. If missing data will not be collected.|
|view-preset|Required to retrieve presets. ***Mandatory***, if missing the inventory will not run.|
|view-projects|Required to retrieve projects. ***Mandatory***, if missing the inventory will not run.|
|view-project-params|Required to retrieve projects params. ***Mandatory***, if missing the inventory will not run.|

*Note: on tenants with access management v1 or v2 activated, the roles/permissions are checked at tenant level.*

#### For SCA
Recommended roles: "SCA Manager" and "Access Control Manager", or the minimum permissions:
|Permissions|Description|
|---|---|
|manage-users and/or manage-teams|Required to retrieve users and teams. If missing data will not be collected.|
|manage-authentication-providers|Required to retrieve external IdP configurations. If missing data will not be collected.|
|manage-roles|Required to retrieve roles. If missing data will not be collected.|
|view|Required to retrieve projects, scans, and results. ***Mandatory***, if missing the inventory will not run.|

## Notice

Tooling developed using Python. Please use Python3!
