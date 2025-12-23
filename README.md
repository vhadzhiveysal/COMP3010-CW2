# COMP3010-CW2

# BOTSv3 Incident Analysis

## Introduction
(To be completed)

## SOC Roles & Incident Handling Reflection
(To be completed)

## Installation & Data Preparation
### BOTSv3 Dataset Ingestion and Validation

The BOTSv3 dataset was successfully installed into Splunk Enterprise following the
official Splunk BOTSv3 repository instructions. The dataset
contained 2,083,056 events across multiple source types, confirming
successful indexing.

A screenshot of the Splunk Data Summary page and validation searches are provided
in the evidence folder.

## Guided Questions – AWS & Endpoint Analysis
### Question 1 – IAM Users Accessing AWS Services

To identify IAM users accessing AWS services within Frothly’s AWS environment,
CloudTrail logs were analysed using the `aws:cloudtrail` sourcetype. AWS
CloudTrail records all API activity, including both successful and unsuccessful
service access attempts.

The following SPL query was used to extract unique IAM usernames:

```
index=botsv3 sourcetype=aws:cloudtrail
| stats count by userIdentity.userName
| sort userIdentity.userName
```

The analysis identified four IAM users that accessed AWS services during the incident timeframe:
- bstoll
- btun
- splunk_access
- web_admin
This information is crucial for SOC investigations, because it establishes which identities were active in the AWS environment,
and helps to narrow the scope of potential misconfigurations, compromised credentials, or malicious activity.

## Conclusion
(To be completed)

## References
(To be completed)

## Video Presentation
(To be added)
