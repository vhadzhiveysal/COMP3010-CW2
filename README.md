# COMP3010-CW2

# BOTSv3 Incident Analysis

## Introduction
Security Operations Centres (SOCs) play a critical role in detecting, analysing,
and responding to cyber security incidents across modern enterprise
environments. These environments increasingly rely on a combination of cloud
infrastructure, endpoint systems, and network services, all of which generate
large volumes of security-relevant telemetry.

This report documents an individual security investigation conducted using the
Boss of the SOC version 3 (BOTSv3) dataset, a realistic Capture The Flag (CTF)
exercise developed by Splunk. BOTSv3 simulates a multi-stage security incident
within a fictional brewing company named Frothly, providing diverse log sources
including AWS CloudTrail logs, S3 access logs, endpoint telemetry, and system
hardware data.

The primary objective of this investigation was to analyse AWS-related activity
and endpoint behaviour using Splunk’s Search Processing Language (SPL), following
a SOC-style investigative workflow. The scope of the analysis focused on IAM
activity, multi-factor authentication usage, cloud storage misconfigurations,
object uploads to public S3 buckets, and endpoint operating system anomalies.

It is assumed that all log data provided within the BOTSv3 dataset is complete
and accurately represents Frothly’s simulated environment during the incident
timeframe. No additional log sources were introduced beyond those available
in the dataset.

The report is structured to reflect professional SOC documentation practices.
It begins with a reflection on SOC roles and incident handling, followed by
documentation of the Splunk installation and data preparation process. The core
of the report presents guided question analysis supported by SPL queries and
evidence, before concluding with key findings and recommendations for improving
detection and response capabilities.

## SOC Roles & Incident Handling Reflection
Security Operations Centres typically operate using a tiered model, where
analysts are assigned responsibilities based on the complexity and severity of
security events. Tier 1 analysts focus on initial alert triage and monitoring,
Tier 2 analysts perform deeper investigation and correlation, while Tier 3
analysts handle advanced threat hunting, incident response coordination, and
long-term remediation.

Within the BOTSv3 exercise, many of the tasks performed align closely with the
responsibilities of a Tier 2 SOC analyst. The investigation required analysing
multiple log sources, correlating events across cloud and endpoint telemetry,
and identifying security-relevant misconfigurations rather than responding to
pre-defined alerts alone.

The identification of IAM users accessing AWS services and the analysis of API
activity without multi-factor authentication reflect the detection and analysis
phases of incident handling. These activities support early identification of
credential misuse or policy violations and would typically be triggered by
automated alerts within a production SOC environment.

The discovery of a publicly accessible S3 bucket and subsequent identification
of an uploaded file demonstrates the escalation from detection to response.
From a SOC perspective, this would likely involve incident containment actions
such as revoking public access, reviewing access logs for further abuse, and
notifying cloud infrastructure or data protection teams.

Endpoint analysis using `winhostmon` highlights the importance of asset
visibility and configuration management during incident response. Identifying
endpoints running non-standard operating system editions enables SOC teams to
prioritise monitoring, patching, or isolation of potentially vulnerable systems.

Finally, the BOTSv3 exercise reinforces the importance of recovery and
post-incident improvement. Lessons learned from cloud misconfigurations and
inconsistent endpoint configurations can inform improved detection rules,
policy enforcement, and preventative controls such as mandatory MFA
requirements and automated cloud security posture management.

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

### Question 8 – Endpoint with a Different Windows OS Edition

Windows endpoint telemetry was analysed using the `winhostmon` sourcetype to
identify inconsistencies in operating system editions across Frothly’s
environment. An initial comparison showed that one endpoint was running a
different Windows edition compared to the rest of the hosts.

The following SPL query was used to identify the outlier system:

`index=botsv3 sourcetype=winhostmon | stats count by host OS`

This analysis identified the host BSTOLL-L as the endpoint running a
different Windows OS edition. The fully qualified domain name (FQDN) was
confirmed through correlation with other data sources within the dataset,
resulting in the following endpoint identification: `BSTOLL-L.froth.ly`

From a SOC perspective, identifying endpoints with non-standard operating system
configurations is important, as such systems may represent legacy assets,
misconfigurations, or increased attack surface requiring closer monitoring.

## Conclusion
(To be completed)

## References
(To be completed)

## Video Presentation
(To be added)
