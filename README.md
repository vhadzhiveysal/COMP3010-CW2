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

### Question 2 – Detecting AWS API Activity Without MFA

AWS CloudTrail logs provide indicators of whether MFA was used during API requests. To identify AWS API activity occurring without MFA,
CloudTrail events were analysed while excluding console login events.

The following SPL query was used:

```
index=botsv3 sourcetype=aws:cloudtrail
| search NOT eventName=ConsoleLogin *mfa*
```

Upon searching through the 'interesting fields' I found a field by the name of `userIdentity.sessionContext.attributes.mfaAuthenticated`, which
indicates whether MFA was used during an API request. Values of false represent API activity executed without MFA, which is an important 
security concern and a common SOC alerting condition.

I added `| stats count by userIdentity.sessionContext.attributes.mfaAuthenticated` to the main query and found that there were 2155 counts of no MFA authentication, and 0 counts of it having MFA authentication.

### Question 3 – Processor Information on Web Servers

To identify the processor used on Frothly’s web servers, host-level hardware
telemetry was analysed using the `hardware` sourcetype. This data source
contains detailed system information including CPU models, memory, storage,
and network interface details.

The following SPL query was used to list processor information across
hosts:
`index=botsv3 sourcetype=hardware`

The analysis revealed that the web servers consistently use the following
processor model: E5-2676

Understanding processor architecture is relevant to SOC operations, as it
supports asset profiling, capacity planning, and vulnerability assessment.
Certain exploits and performance-based attacks may target specific CPU
architectures, making accurate hardware visibility an important component of
endpoint security monitoring.

### Questions 4–6 – Publicly Accessible S3 Bucket Misconfiguration

A review of AWS CloudTrail logs identified a misconfiguration event where an S3
bucket was made publicly accessible. Such misconfigurations are a common cloud
security risk and can result in unintended data exposure.

The following SPL query was used to identify S3 permission changes:
`index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl`

Analysis of the event revealed that the API call enabling public access (the earliest event in the list) had the
following attributes:

Event ID: ab45689d-69cd-41e7-8705-5350402cf7ac
IAM Username (Bud's username): bstoll 
S3 Bucket Name: frothlywebcode

The event ID was one of the first attributes listed in the event.
The username attribute was found easier through opening the `userIdentity.userName` field.
The S3 bucket name attribute was found easier through opening the `requestParameters.bucketName` field.

This activity demonstrates how improper access control list (ACL) configuration
can introduce security risks within cloud environments. From a SOC perspective,
monitoring PutBucketAcl events is critical for early detection of accidental or
malicious exposure of cloud storage resources.

### Question 7 – File Uploaded to the Public S3 Bucket

S3 access logs were analysed to determine whether any objects were uploaded 
while the bucket was exposed. The `aws:s3:accesslogs` sourcetype records detailed
object-level operations, including uploads and HTTP response codes.

An initial keyword-based search for text files ultimately revealed the text file
being searched for.

`index=botsv3 sourcetype="aws:s3:accesslogs" *.txt*`
Three events showed up each detailing a `OPEN_BUCKET_PLEASE_FIX.txt` file.

## Conclusion
(To be completed)

## References
(To be completed)

## Video Presentation
(To be added)
