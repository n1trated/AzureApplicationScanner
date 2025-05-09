# Azure Application Detector

This tool helps detect the existence of specific applications in Azure tenants by analyzing authentication error messages.

## Principle

The tool leverages error codes in the Azure AD authentication mechanism to determine if an application exists:
- Error code 700016 is returned when the application ID does not exist in the tenant
- Error code 7000215 is returned when the application ID exists but an incorrect client_secret is provided

### Example Error Messages

#### When Application Does Not Exist (Error Code 700016):
```json
{
  "error": "unauthorized_client",
  "error_description": "AADSTS700016: Application with identifier '6583ff8c-9c43-450b-a63d-6934afda87b7' was not found in the directory 'tenantName'. This can happen if the application has not been installed by the administrator of the tenant or consented to by any user in the tenant. You may have sent your authentication request to the wrong tenant. Trace ID: 4585a0a0-6672-48cb-9552-e1e0ed784100 Correlation ID: cb41a714-75ad-497a-b028-de92e1e52479 Timestamp: 2025-04-23 02:36:18Z",
  "error_codes": [700016],
  "timestamp": "2025-04-23 02:36:18Z",
  "trace_id": "4585a0a0-6672-48cb-9552-e1e0ed784100",
  "correlation_id": "cb41a714-75ad-497a-b028-de92e1e52479",
  "error_uri": "https://login.microsoftonline.com/error?code=700016"
}
```

#### When Application Exists But Client Secret Is Invalid (Error Code 7000215):
```json
{
  "error": "invalid_client",
  "error_description": "AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID, for a secret added to app '6583ff8c-9c43-450b-a63d-6934afda87b8'. Trace ID: 0e94f0c2-80a2-4505-a297-5e51b6953800 Correlation ID: 57b6d444-a89d-4375-ab08-ac1724976895 Timestamp: 2025-04-23 02:35:17Z",
  "error_codes": [7000215],
  "timestamp": "2025-04-23 02:35:17Z",
  "trace_id": "0e94f0c2-80a2-4505-a297-5e51b6953800",
  "correlation_id": "57b6d444-a89d-4375-ab08-ac1724976895",
  "error_uri": "https://login.microsoftonline.com/error?code=7000215"
}
```

This tool analyzes these error responses to determine if the application exists in the target tenant.

## Installation

### Dependencies

```bash
pip install requests
```

## Usage

```bash
python azure_app_detector.py -t <tenant_domain> -f <client_id_list_file> [-o <output_file>] [-w <concurrent_threads>] [-d <delay_seconds>] [-v]
```

### Parameters

- `-t, --tenant`: Required, target Azure tenant domain
- `-f, --file`: Required, file path containing the client_id list (supports TXT or CSV formats)
- `-o, --output`: Optional, result output file path
- `-w, --workers`: Optional, number of concurrent threads (default: 10)
- `-d, --delay`: Optional, delay between requests in seconds (default: 0.5)
- `-v, --verbose`: Optional, output detailed information

### Input File Formats

The tool supports the following two input file formats:

1. **Simple Text Format**: One App ID per line
```
6583ff8c-9c43-450b-a63d-6934afda87b7
9b41a714-75ad-497a-b028-de92e1e52479
...
```

2. **CSV Format**: Comma-separated CSV file with a header row, must include an `appId` column, and optionally a `displayName` column.(the example file is exported from 'Enterprise Application list' under EntraID function)
```
id	displayName	appId	homepageUrl	createdDateTime	applicationType	accountEnabled	...
1	AppName1	6583ff8c-9c43-450b-a63d-6934afda87b7	https://example.com	2023-01-01	...
2	AppName2	9b41a714-75ad-497a-b028-de92e1e52479	https://example.com	2023-01-01	...
...
```

Note: The CSV format file must include an `appId` column. If a `displayName` column is included, the output will display both the application name and ID.

## Examples

```bash
# Basic usage
python azure_app_detector.py -t contoso.onmicrosoft.com -f client_ids.txt

# Using a CSV format file
python azure_app_detector.py -t contoso.onmicrosoft.com -f applications.csv -o results.json

# Using 20 threads and longer delay
python azure_app_detector.py -t contoso.onmicrosoft.com -f applications.csv -w 20 -d 1.0 -v
```

## Sample Output

Console output:
```
[INFO] Starting detection in tenant contoso.onmicrosoft.com
[INFO] Loaded 100 application IDs
[FOUND] App Name: Sample App 1, App ID: 6583ff8c-9c43-450b-a63d-6934afda87b7
[FOUND] App Name: Sample App 2, App ID: 9b41a714-75ad-497a-b028-de92e1e52479

[RESULT] Total applications checked: 100
[RESULT] Found existing applications: 2

Existing application list:
- Name: Sample App 1, ID: 6583ff8c-9c43-450b-a63d-6934afda87b7
- Name: Sample App 2, ID: 9b41a714-75ad-497a-b028-de92e1e52479
```

## Defender's Perspective

### Monitoring Authentication Failures

Defenders can monitor application enumeration attempts by reviewing authentication failures in Microsoft Entra ID. These logs can be found in:

**EntraID → Monitoring → Sign-in logs → Service principal sign-ins**

![Sign-in Logs](imgs/Sign-in%20logs.png)

Failed authentication attempts from this tool will be recorded with error codes 700016 (application not found) or 7000215 (invalid client secret). Administrators can use these logs to detect reconnaissance activities targeting their applications.

### Detection using Log Analytics KQL

Defenders can create alerts to detect scanning activities by implementing the following KQL query in Log Analytics. This query identifies potential application enumeration attempts by detecting when a single IP address fails authentication with more than 5 different client IDs within a 1-hour window:

```kql
// Detect potential application enumeration attempts
AADServicePrincipalSignInLogs
| where ResultType == "7000215" or ResultType == "700016"
| where TimeGenerated > ago(24h)
| summarize 
    FailedAppCount = dcount(AppId),
    FailedApps = make_set(AppId),
    FailedCount = count() 
    by IPAddress, bin(TimeGenerated, 24h)
| where FailedAppCount >= 5
| project 
    TimeGenerated,
    IPAddress, 
    FailedAppCount,
    FailedCount,
    FailedApps
| order by FailedAppCount desc
```

This query can be used to:
- Create custom alerts in Azure Sentinel
- Generate email notifications when suspicious patterns are detected
- Trigger automated remediation actions such as temporary IP blocking

## Precautions

- Please set reasonable concurrent thread numbers and delay times to avoid excessive pressure on the target tenant
- Ensure you have legal permission to test the target tenant before use
- This tool is for security research and authorized testing only 