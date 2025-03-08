---
title: "Advanced Hunting"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [Intune, MAC] 
published: false
published_at: 2024-12-31 08:00
---

# Alerts and Behaviors

### AlertEvidence
`AlertEvidence` スキーマは、アラートをトリガーしたイベントに関する追加情報を提供します。 これには、アラートに関連するファイル名、プロセス名、レジストリキー、IPアドレス、URLなどのエンティティ情報が含まれます。

**Use Cases:**

- **Security Investigation:** Investigators can use AlertEvidence to drill into *all indicators involved in a specific alert*. For example, given an alert ID or title, you might retrieve the list of malicious files, URLs, or affected devices for that alert to understand its scope. This helps incident responders see what the alert touched.  
  - *Basic Query:* Retrieve evidence entities for a particular alert (by AlertId or Title). This lists all files, IPs, etc. involved in that alert for further analysis. For example:  
    ```kql
    // Get all evidence entities for a specific alert by title
    AlertEvidence
    | where Title == "Suspicious PowerShell Behavior" 
    | project Timestamp, EntityType, EvidenceRole, FileName, SHA1, AccountName, DeviceName
    ```  
  - *Advanced Query:* Identify if an indicator from one alert appears in others (linking related incidents). For instance, find file hashes that have been evidence in **multiple** distinct alerts, which may indicate a widespread threat:  
    ```kql
    // Find file hashes that appear in more than one alert (potentially spreading)
    AlertEvidence
    | where EntityType == "File" and isnotempty(SHA1)
    | summarize AlertCount=dcount(AlertId), Alerts=make_set(Title) by SHA1, FileName
    | where AlertCount > 1
    | project FileName, SHA1, AlertCount, Alerts
    ```  
    This query hunts for files that triggered multiple alerts, helping investigators connect related alerts or see if a known malicious file is recurring across incidents.

- **Threat Hunting:** Threat hunters can query AlertEvidence for patterns across alerts to proactively identify threats. For example, one might search for all alert evidences related to a particular **MITRE ATT&CK technique** or a known malware family, indicating that technique or malware was detected. Another hunting approach is to find alerts involving certain entities (like unusual external IP ranges or domains).  
  - *Basic Query:* Hunt for alerts that involved a specific threat family or ATT&CK technique. For instance, find all alerts where the evidence indicates **phishing** activity (MITRE technique T1566) or a known malware family:  
    ```kql
    // Hunt for alert evidences indicating phishing attempts (ATT&CK T1566)
    AlertEvidence
    | where AttackTechniques has "T1566"  // phishing technique
      or ThreatFamily == "Phishing"
    | project Timestamp, AlertId, Title, EvidenceRole, RemoteUrl, AccountUpn
    ```  
    This returns alerts (with their evidences) related to phishing.  
  - *Advanced Query:* Identify *common targets or sources* in alerts, such as an IP address that appears as evidence in multiple alerts (possibly a command-and-control server). For example, find any **IP address** that was the remote IP in alert evidences for more than one device:  
    ```kql
    // Find suspicious IPs that appear in alerts on multiple devices
    AlertEvidence
    | where isnotempty(RemoteIP)
    | summarize DevicesAffected=dcount(DeviceId), AlertCount=dcount(AlertId) by RemoteIP
    | where DevicesAffected > 1
    | sort by AlertCount desc
    ```  
    This surfaces IPs that have triggered alerts on multiple machines, a possible sign of a widespread attacker infrastructure.

- **Compliance Check:** In a security operations context, you can use AlertEvidence to verify that threats are being remediated in compliance with policy (e.g. high-severity alerts addressed within an SLA, or malicious artifacts removed). For example, you might check for any high-severity alert evidences older than a certain date (indicating potential overdue incidents), or ensure that malicious files identified by alerts are no longer present in the environment.  
  - *Basic Query:* List all **High severity** alerts (via their evidence entries) that are older than 7 days, which could indicate incidents that potentially haven’t been fully resolved within the expected timeframe:  
    ```kql
    // Identify high-severity alerts (via evidence) older than 7 days
    AlertEvidence
    | where Severity == "High" and Timestamp < ago(7d)
    | summarize Alerts=dcount(AlertId) by Title, max(Timestamp)
    ```  
    This yields high-severity alert titles and the last time they were seen, for compliance tracking of incident response SLAs.  
  - *Advanced Query:* Ensure malicious files from alerts have been remediated. For example, take file hashes from recent malware alerts and check if those files ran on any device **after** the alert time (which would mean the threat persisted, a compliance gap in remediation):  
    ```kql
    // Check if files from malware alerts executed again after the alert (remediation check)
    let recentMalware = AlertEvidence
      | where EntityType == "File" and ThreatFamily != "" and Timestamp > ago(14d)
      | project AlertId, SHA1, AlertTime=Timestamp;
    recentMalware
    | join kind=inner (
        DeviceProcessEvents 
        | project SHA1, ProcessCreationTime
      ) on SHA1
    | where ProcessCreationTime > AlertTime  // execution after alert was raised
    | project SHA1, AlertId, AlertTime, ProcessCreationTime, DeviceName
    ```  
    This cross-table query finds any file (by SHA1 hash) that was identified in a recent malware alert and then was executed on a device *after* that alert. Security teams can use this to verify that malware files were quarantined or removed as required by policy, flagging any that reappeared.

### AlertInfo
**Schema Description:** The `AlertInfo` table contains a record for each security alert in Microsoft 365 Defender, including alerts from Defender for Endpoint, Defender for Office 365, Defender for Cloud Apps, and Defender for Identity ([AlertInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table#:~:text=AlertInfo)). Each alert record includes high-level info such as the alert **Title**, **Category** (type of threat or breach activity), **Severity** (Low, Medium, High), **ServiceSource** (which product or service generated the alert), and any mapped **MITRE ATT&CK techniques** ([AlertInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table#:~:text=Column%20name%20Data%20type%20Description,that%20provided%20the%20alert%20information)) ([AlertInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table#:~:text=,activity%20that%20triggered%20the%20alert)). This table is used to **view and filter alerts**, often as a starting point for investigations or to gauge your threat landscape (e.g., count of alerts by severity or category).

**Use Cases:**

- **Security Investigation:** Analysts use AlertInfo to retrieve details about a specific alert or to find related alerts by category or severity. For example, when investigating an incident, you might pull all alerts for the affected device or all alerts in the same timeframe to see the bigger picture.  
  - *Basic Query:* Get all details of a particular alert by its ID (or title). This helps an investigator quickly gather the context of that alert (severity, category, etc.):  
    ```kql
    // Fetch a specific alert by AlertId
    AlertInfo
    | where AlertId == "<ALERT-ID-123>"
    ```  
    *(Replace `<ALERT-ID-123>` with the actual AlertId of interest.)* This returns the full alert record, including Title, Category, Severity, etc., which is useful as a summary for incident reporting.  
  - *Advanced Query:* Investigate all alerts related to a specific device or user during an incident. For example, if a device is suspected to be compromised, list all alerts on that device in the last 24 hours:  
    ```kql
    // Alerts on a specific device in the last day (by device name)
    AlertInfo
    | where DeviceName == "HR-WKSTN-001.contoso.com"
      and Timestamp > ago(1d)
    | project Timestamp, Title, Severity, Category, ServiceSource
    | sort by Timestamp asc 
    ```  
    This query compiles a timeline of alerts on *HR-WKSTN-001* over the last day, aiding investigators in understanding the sequence of malicious activities and their types.

- **Threat Hunting:** The AlertInfo table can be queried to find patterns or clusters of alerts that might indicate undetected issues or widespread campaigns. Hunters often look at alert trends by category or ATT&CK technique to hypothesize where to dig deeper.  
  - *Basic Query:* Hunt for **multiple low-severity alerts that could collectively indicate a bigger issue**. For instance, a spike in multiple “failed logon” or “password spray” low-severity alerts might warrant attention. A simple query could count alerts by category or title:  
    ```kql
    // Count of alerts by title in the last 7 days (identify unusual alert spikes)
    AlertInfo
    | where Timestamp > ago(7d)
    | summarize AlertCount = count() by Title, Severity
    | sort by AlertCount desc
    ```  
    Reviewing the most frequent alerts may highlight an ongoing issue (e.g., many password spray alerts indicating a possible brute-force attack attempt).  
  - *Advanced Query:* Proactively identify **gaps in coverage or emerging attack techniques**. For example, list any ATT&CK techniques that have *no* alerts in the past month (perhaps indicating potential blind spots):  
    ```kql
    // Find MITRE techniques not seen in alerts in the past 30 days
    let techniquesSeen = AlertInfo
      | where Timestamp > startofday(ago(30d))
      | mv-expand technique = split(AttackTechniques, ",")
      | summarize by technique;
    AttckTechniqueReferences  // hypothetical reference of all techniques
    | where TechniqueID !in (techniquesSeen.technique)
    ```  
    *(Note: This assumes you have a reference list `AttckTechniqueReferences` of all technique IDs.)* The idea is to reveal which techniques haven’t been detected in alerts, which might be areas to validate for coverage or test via red team exercises.

- **Compliance Check:** In terms of security operations, compliance could mean ensuring that alerts are handled according to policy or that detection coverage meets certain standards. With AlertInfo, one can check if all high-severity alerts have been resolved within a timeframe, or ensure categories like data leak alerts are not occurring (policy compliance).  
  - *Basic Query:* Identify any **high severity alerts older than X days that are still active**, which may violate incident response SLAs. (AlertInfo doesn’t directly store “resolved” status, but analysts often assume if an alert is still listed and old, it might be unresolved.) For example:  
    ```kql
    // High severity alerts older than 14 days (potentially overdue)
    AlertInfo
    | where Severity == "High" and Timestamp < ago(14d)
    | project AlertId, Title, Category, Timestamp
    ```  
    Security managers can review such a list to ensure no critical alert has been ignored or open beyond the allowed period.  
  - *Advanced Query:* **Policy violation alerts** – ensure that none (or few) are occurring. For instance, if your organization has a policy against using unsanctioned cloud apps, you might have alerts in the *Cloud App* category when that policy is broken. You can check how many such alerts fired in a period:  
    ```kql
    // Count of policy-related alerts (e.g., data leak or DLP) in last 30 days
    AlertInfo
    | where Category in ("Data Loss Prevention", "DataLeak", "ShadowIT")
      and Timestamp > ago(30d)
    | summarize AlertsCount = count()
    ```  
    If this count is above zero (or above a threshold), it indicates compliance issues (e.g., users emailing sensitive data, using unsanctioned apps, etc.). The security team might treat any occurrence as a compliance failure to be addressed via training or controls. This use of AlertInfo helps monitor adherence to security policies through the lens of alerts.

### BehaviorEntities (Preview)
**Schema Description:** The `BehaviorEntities` table (preview) contains information about **behaviors** detected by Microsoft Defender for Cloud Apps (formerly MCAS) ([BehaviorEntities table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorentities-table#:~:text=The%20,return%20information%20from%20this%20table)). A *behavior* in Defender XDR is a higher-level abstraction derived from one or more raw events, providing contextual insight into user or entity actions ([BehaviorEntities table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorentities-table#:~:text=Behaviors%20are%20a%20type%20of,Read%20more%20about%20behaviors)). This table lists the **entities involved in those behaviors**. For each behavior, it can enumerate associated entities (users, files, devices, etc.) along with their roles. Key fields include **BehaviorId** (unique ID of the behavior), **ActionType** (type of behavior/activity detected), **EntityType** and **EntityRole** (what type of entity and whether it’s the actor or target) ([BehaviorEntities table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorentities-table#:~:text=,that%20provided%20information%20for%20the)) ([BehaviorEntities table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorentities-table#:~:text=,is%20impacted%20or%20merely%20related)), plus context like filenames, IPs, account info, etc. Essentially, BehaviorEntities is similar in concept to AlertEvidence, but for *Cloud App behavioral alerts*, providing the who/what involved in a cloud app alert or anomaly.

**Use Cases:**

- **Security Investigation:** When a Defender for Cloud Apps alert (behavior) triggers – for example, “Impossible Travel” or “Mass download by user” – investigators can use BehaviorEntities to see *which users, files, or other objects* are involved. This helps clarify what the behavior alert is about.  
  - *Basic Query:* Fetch entities for a specific Cloud App behavior alert by its BehaviorId. For instance, if investigating an “Impossible Travel” alert, list the user and IP entities that were part of that behavior:  
    ```kql
    // Retrieve entities involved in a specific behavior alert
    BehaviorEntities
    | where BehaviorId == "<Behavior-ID>"
    ```  
    This gives all entities (e.g., the user account, the source and destination locations as IP entities) tied to that alert. Analysts can quickly identify the user who triggered the anomaly and any related entity (maybe a file or device).  
  - *Advanced Query:* Correlate behavior alerts with device or identity info for richer context. For example, join BehaviorEntities with IdentityInfo to get department or job role of the user involved (useful to assess impact or intent):  
    ```kql
    // Enrich a cloud app behavior's user entity with identity details
    BehaviorEntities
    | where BehaviorId == "<Behavior-ID>" and EntityType == "User"
    | join kind=leftouter IdentityInfo on $left.AccountObjectId == $right.AccountObjectId
    | project BehaviorId, ActionType, AccountDisplayName, Department, Country = AccountCountry
    ```  
    This might show, for instance, that a user from Finance performed an unusual cloud activity from a foreign country – valuable context for the investigator.

- **Threat Hunting:** BehaviorEntities can be queried to uncover suspicious patterns in cloud usage across the tenant – even if they haven’t triggered formal alerts, the behavior records are there to hunt through (since behaviors can be benign or precursors to alerts). Hunters might look for multiple behaviors by the same user or unusual combinations of entities.  
  - *Basic Query:* Find **multiple different behaviors involving the same user**, which could indicate that user account is behaving abnormally. For example:  
    ```kql
    // Users associated with multiple distinct behavior alerts in last 7 days
    BehaviorEntities
    | where Timestamp > ago(7d) and EntityType == "User"
    | summarize BehaviorCount=dcount(BehaviorId), Actions=make_set(ActionType) by AccountUpn
    | where BehaviorCount > 1
    ```  
    This identifies users who had more than one behavior alert (perhaps an impossible travel *and* a mass download), suggesting that account may warrant investigation for compromise.  
  - *Advanced Query:* Hunt for **cloud app behaviors indicating risky file activities**. For instance, find any behavior where a *sensitive file* (if tagged or named a certain way) was accessed in unusual ways:  
    ```kql
    // Potential data exfiltration via cloud – e.g., multiple file downloads by one user
    BehaviorEntities
    | where EntityType == "File" and FileName has "Confidential"
    | join kind=inner (BehaviorEntities | where EntityType == "User") on BehaviorId
    | project Timestamp, BehaviorId, User=AccountUpn, FileName, ActionType
    ```  
    Here we filter behaviors that involve files named “Confidential” and pair them with the user involved in the same BehaviorId. This could reveal if a user downloaded many confidential files (the ActionType might be something like *MassFileDownload* in Cloud App events).

- **Compliance Check:** In cloud app monitoring, compliance might involve ensuring that certain activities (like accessing sensitive data from unsanctioned locations or violating data residency) are flagged. BehaviorEntities can help verify if such policy-violation behaviors occurred and who was involved, supporting internal compliance audits.  
  - *Basic Query:* Check if any **sensitive SharePoint content access** behaviors were recorded (indicative of possible policy violations). For example, if your organization has a policy against mass deletion of files, and Defender for Cloud Apps monitors that:  
    ```kql
    // Find any behavior alerts related to mass file deletion (compliance)
    BehaviorEntities
    | where ActionType == "MassDeletionActivity" 
    | summarize Count=count() by BehaviorId
    ```  
    If any such behaviors exist, it indicates compliance issues (someone deleting large numbers of files, potentially in violation of data retention policies).  
  - *Advanced Query:* Ensure **cloud access policies** (like impossible travel) are being enforced. For instance, detect any user that circumvented MFA or other controls – one proxy is to look at *Behaviors that got downgraded in severity or not turned into full alerts*. While BehaviorEntities alone may not have “policy passed/failed” info, you can use it with BehaviorInfo (which contains alert info for behaviors). For example, to list all *Behavior alerts of type “ImpossibleTravel” and check if the user is an admin (a bigger compliance concern)*:  
    ```kql
    // List impossible travel behaviors and flag if user is an admin
    let adminUsers = IdentityInfo | where JobTitle contains "Admin" or Roles has "Global Administrator" | distinct AccountObjectId;
    BehaviorInfo
    | where Description startswith "Impossible travel"
    | join kind=inner (BehaviorEntities | where EntityType == "User") on BehaviorId
    | extend IsAdmin = iff(AccountObjectId in (adminUsers), "Yes", "No")
    | project Timestamp, AccountUpn, IsAdmin, Description
    ```  
    This identifies “Impossible travel” incidents and whether the user involved is an admin. A compliance officer might specifically review cases where privileged accounts logged in from impossible locations (since that violates not just policy but could be critical). This cross-table query helps highlight compliance-relevant anomalies (like admins breaching location policy).

### BehaviorInfo (Preview)
**Schema Description:** The `BehaviorInfo` table (preview) contains information about **behavior-based alerts** from Microsoft Defender for Cloud Apps ([BehaviorInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorinfo-table#:~:text=The%20,return%20information%20from%20this%20table)). Each entry in BehaviorInfo is essentially an *alert record for a cloud app behavior*, similar to how AlertInfo is for traditional alerts. It includes details like **Description** of the behavior, **Category** (threat types or policy names), associated **MITRE techniques**, and time bounds of the behavior (StartTime/EndTime) ([BehaviorInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorinfo-table#:~:text=,the%20notable%20component%20or%20activity)) ([BehaviorInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorinfo-table#:~:text=,activity%20related%20to%20the%20behavior)). Since behaviors provide context for potentially suspicious activities in cloud services, this table is valuable for understanding *what the alert is and its scope* (duration, techniques, etc.). In short, BehaviorInfo is the Cloud Apps counterpart to AlertInfo, summarizing each behavior alert.

**Use Cases:**

- **Security Investigation:** When a Cloud App Security alert is raised (for example, “Multiple file deletion” or “Impossible travel”), an analyst can look at BehaviorInfo to get the details of that alert: what happened, when it started/ended, and what techniques or categories it falls under. This helps in triaging the alert’s severity and impact quickly.  
  - *Basic Query:* Retrieve the details of a specific behavior alert by ID or description. For instance, if investigating an alert about mass downloads, find that alert’s info:  
    ```kql
    // Get a cloud app behavior alert by ID
    BehaviorInfo
    | where BehaviorId == "<Behavior-ID>"
    ```  
    This will return fields like Description (e.g. *“Mass download of files from SharePoint”*), Severity (if available), Category, etc., giving a summary of the alert.  
  - *Advanced Query:* List all cloud app behavior alerts related to a particular **user or app** in a timeframe. For example, if a particular user is under investigation, list their cloud app alerts in last 30 days to see if there's a pattern:  
    ```kql
    // Cloud app alerts for a specific user in last 30 days
    BehaviorInfo
    | where Timestamp > ago(30d) and AccountUpn == "alice@contoso.com"
    | project Timestamp, Description, Categories, AttackTechniques
    | order by Timestamp desc
    ```  
    This provides a timeline of behavior alerts involving Alice (e.g., suspicious OAuth app usage, impossible travel, etc.), helping an investigator piece together if Alice’s account is compromised or violating policies.

- **Threat Hunting:** Threat hunters can use BehaviorInfo to find anomalies that might not have been escalated or to correlate cloud behaviors with other incidents. Because behaviors can indicate things like unusual login patterns or data access, hunters might search for specific descriptions or categories across the environment.  
  - *Basic Query:* Look for **multiple behavior alerts of the same type across different users**, which might indicate a broader issue. For instance, if several users trigger “Impossible travel” alerts, that could suggest a campaign of account compromise attempts.  
    ```kql
    // Count of cloud app behavior alerts by description (last 7 days)
    BehaviorInfo
    | where Timestamp > ago(7d)
    | summarize AlertCount = count() by Description
    | sort by AlertCount desc
    ```  
    If “Impossible travel” or “OAuth consent grant” behaviors appear frequently, the hunter might investigate further, as this could be an ongoing attack pattern (like multiple users being targeted).  
  - *Advanced Query:* Identify **long-running or repeated behaviors** that could indicate stealthy malicious activity. For example, find behavior alerts that have a long duration between StartTime and EndTime (which might mean prolonged data access):  
    ```kql
    // Find behavior alerts with duration over 1 hour
    BehaviorInfo
    | where datetime_diff("minute", EndTime, StartTime) > 60
    | project Description, StartTime, EndTime, AccountUpn
    ```  
    This could catch anomalies like an OAuth app maintaining a connection or a session for an unusually long time (perhaps siphoning data), even if it didn’t trigger an immediate block.

- **Compliance Check:** From a compliance perspective, cloud app behaviors often tie into policies (like data leak prevention, unusual administrative actions, etc.). BehaviorInfo can be used to verify that compliance-related policies are firing and being addressed. For example, alerts about downloading sensitive files or logging in from restricted locations can be monitored.  
  - *Basic Query:* Check for **compliance-related cloud app alerts**, such as those indicating violations of data handling policies. For instance, list any alerts with descriptions containing “Confidential” or categories related to data leaks:  
    ```kql
    // Find any cloud app alerts related to confidential data
    BehaviorInfo
    | where Description contains "Confidential" or Categories has "Data Leak"
    | project Timestamp, Description, AccountUpn
    ```  
    If this returns results, it means users have triggered cloud app policies around confidential data (like downloading or sharing confidential files) – a direct compliance issue that needs follow-up (e.g., ensuring that data was not leaked).  
  - *Advanced Query:* Verify that **critical cloud app alerts receive attention**. For example, if company policy says any “Impossible Travel” alert (which could indicate a stolen credential) must result in a password reset, you could cross-check BehaviorInfo with subsequent login events. A simpler proxy is to ensure no high-severity behavior alerts remain unresolved. While BehaviorInfo doesn’t show resolution, you could assume that older ones should be closed. So, for instance:  
    ```kql
    // High-severity behavior alerts older than 7 days (potentially not addressed)
    BehaviorInfo
    | where Severity == "High" and Timestamp < ago(7d)
    ```  
    *(If `Severity` field exists for behaviors – as this is preview, it may or may not.)* The idea is that any high severity cloud app alert older than a week suggests a gap in response. Compliance teams might use this to audit whether security followed up on those alerts (password resets, user contacted, etc.). They can then reconcile this list with incident tickets.

---

# Apps and Identities

### AADSignInEventsBeta
**Schema Description:** `AADSignInEventsBeta` is a **beta** table that provides raw sign-in event data from Microsoft Entra ID (Azure AD) interactive and non-interactive sign-ins ([AADSignInEventsBeta table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table#:~:text=The%20,table)). It was introduced to allow hunting through Azure AD sign-in logs in Defender until the data is fully merged into `IdentityLogonEvents` ([AADSignInEventsBeta table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table#:~:text=The%20,table)). This table includes fields you’d find in Azure AD sign-in logs, such as **Application** used, **LogonType** (interactive, RDP, etc.), **CorrelationId/SessionId** for the sign-in, user details (DisplayName, UPN, ObjectId), and status/error information like **ErrorCode** for failed logins ([AADSignInEventsBeta table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table#:~:text=,in%20event)) ([AADSignInEventsBeta table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table#:~:text=the%20duration%20of%20the%20visit,external)). Essentially, it surfaces cloud authentication events (user logons to Azure AD-connected apps and services) for hunting.

**Use Cases:**

- **Security Investigation:** Investigators can query this table to gather details on a user’s Azure AD login activity when investigating account compromise or suspicious logon attempts. For example, if a user's account is suspected of being compromised, reviewing their recent sign-in events (times, locations, device info, success/failure) is critical.  
  - *Basic Query:* Retrieve the last few Azure AD sign-in events for a specific user to see if there were unusual login attempts (e.g., odd hours or error codes indicating MFA failures):  
    ```kql
    // Last 5 sign-in events for a specific user
    AADSignInEventsBeta
    | where AccountUpn == "jdoe@contoso.com"
    | sort by Timestamp desc
    | take 5
    | project Timestamp, Application, LogonType, IsExternalUser, IsGuestUser, ErrorCode
    ```  
    This shows when and how John Doe logged in, whether he was flagged as external/guest, and any error codes (like sign-in failures). An investigator can spot if John had a series of failed logins or logins from unusual apps.  
  - *Advanced Query:* Investigate a suspicious sign-in by correlating it with device information. For instance, if you see an unusual sign-in, you might want to know what device (if any) was associated via Azure AD device ID. One could join with `DeviceInfo` on the AadDeviceId:  
    ```kql
    // Enrich a sign-in event with device info (if device is Azure AD joined)
    AADSignInEventsBeta
    | where AccountUpn == "jdoe@contoso.com" and Timestamp between (datetime(2025-03-01) .. datetime(2025-03-05))
    | join kind=leftouter (DeviceInfo | project AadDeviceId, DeviceName, OSPlatform) on $left.DeviceId == $right.AadDeviceId
    | project Timestamp, AccountDisplayName, Application, DeviceName, OSPlatform, IPAddress, IsExternalUser, ErrorCode
    ```  
    This provides context like which device John used during those logins and whether the device is corporate. If a login came from an unknown device or IP, it stands out in the investigation.

- **Threat Hunting:** Hunters can use AADSignInEventsBeta to find patterns of malicious logon attempts. For example, brute force attacks or token replay attacks might show up as numerous failed logins or unusual user agents. Since this table logs interactive and non-interactive sign-ins, one can search for anomalies in login behavior.  
  - *Basic Query:* Hunt for **failed sign-in patterns** that might indicate password spraying or brute force. For instance, look for multiple failed sign-ins (ErrorCode != 0 indicates failure) across many accounts from the same IP or with the same UserAgent:  
    ```kql
    // Potential password spray: many failed logins from same IP
    AADSignInEventsBeta
    | where ErrorCode != 0 and Timestamp > ago(1d)
    | summarize Attempts=count(), Users=make_set(AccountUpn) by IPAddress, UserAgent
    | where Attempts > 10
    ```  
    This surfaces IPs with lots of failures in a day. If *Users* set contains many different accounts, that’s a typical password spray attack pattern.  
  - *Advanced Query:* Identify suspicious sign-in characteristics, e.g., a rare **UserAgent** that could be an attacker tool. For instance, filter for a specific unusual user agent string known for malicious usage (like `"fasthttp"` library used by some brute force tools ([Detecting 'fasthttp' bruteforce attacks on Entra ID - Rogier Dijkman](https://rogierdijkman.medium.com/detecting-fasthttp-bruteforce-attacks-on-entra-users-42ceb13bf856#:~:text=Detecting%20%27fasthttp%27%20bruteforce%20attacks%20on,indicates%20a%20failed%20login))):  
    ```kql
    // Hunt for sign-ins using a known malicious user agent
    AADSignInEventsBeta
    | where UserAgent contains "fasthttp" or UserAgent contains "python-requests"
    | project Timestamp, AccountUpn, IPAddress, Application, UserAgent, ErrorCode
    ```  
    If such entries appear (especially with many failures), it likely indicates automated attacks or token theft attempts using custom clients. A hunter could also extend this by checking if any of those attempts eventually succeeded (ErrorCode == 0 after many failures).

- **Compliance Check:** In an identity context, compliance might involve ensuring only authorized login methods are used or that all external logins are appropriately restricted. AADSignInEventsBeta can help verify such policies. For example, you can check that legacy authentication isn’t being used (if that’s banned by policy) or that guest/external user access is monitored.  
  - *Basic Query:* Identify any **legacy authentication** attempts (e.g., using older protocols that don’t support modern auth/MFA, if LogonType or Application indicates such). Suppose your org policy disallows legacy protocols; you could search for sign-ins with suspicious LogonType values:  
    ```kql
    // Detect any non-interactive legacy logons (e.g., using Basic Auth)
    AADSignInEventsBeta
    | where LogonType == "Legacy" or Application startswith "Office365/ActiveSync"
    | summarize Count = count() by Application, AccountUpn, LogonType
    ```  
    If this returns results, it means someone is using or attempting legacy auth (like ActiveSync basic authentication), violating policy. This could prompt enforcement of Conditional Access or further investigation of those accounts.  
  - *Advanced Query:* Ensure all **external user logins** follow policy. For instance, if external users (guests) should only access certain applications, you can verify that. Using `IsExternalUser` or `IsGuestUser` flags, list what apps external users are logging into:  
    ```kql
    // External user sign-in overview (last 30 days)
    AADSignInEventsBeta
    | where Timestamp > ago(30d) and IsExternalUser == 1
    | summarize count() by Application, IsGuestUser
    ```  
    This gives a breakdown of which applications are accessed by external identities and whether those were guest accounts. If you see external users accessing an app that policy says only internal employees should use, that’s non-compliant. For example, an external user logging into an internal HR system would be flagged. Security or IAM teams can then adjust access policies accordingly.

### AADSpnSignInEventsBeta
**Schema Description:** `AADSpnSignInEventsBeta` is a beta table for **service principal and managed identity sign-in events** in Microsoft Entra ID ([defender-docs/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md at public · MicrosoftDocs/defender-docs · GitHub](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md#:~:text=The%20,table)). While AADSignInEventsBeta logs user sign-ins, this table logs sign-ins by applications (service principals) or managed identities (often used for automation and services). It includes fields like **ServicePrincipalName/Id**, whether it was a managed identity (`IsManagedIdentity` flag), the **Resource** being accessed (ResourceId, ResourceDisplayName), along with common fields like CorrelationId, IP, error codes, etc. ([defender-docs/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md at public · MicrosoftDocs/defender-docs · GitHub](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md#:~:text=Column%20name%20Data%20type%20Description,in%20event)) ([defender-docs/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md at public · MicrosoftDocs/defender-docs · GitHub](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md#:~:text=,tenant%20of%20the%20resource%20accessed)). It’s useful for hunting through app logins and detecting potential abuse of app credentials or malicious OAuth activities. (Note: Eventually these events will also migrate into IdentityLogonEvents ([defender-docs/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md at public · MicrosoftDocs/defender-docs · GitHub](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md#:~:text=The%20,table)).)

**Use Cases:**

- **Security Investigation:** If there’s suspicion that a malicious app or a compromised service principal token was used, investigators turn to this table. For example, if an OAuth application was granted unwarranted permissions, its usage would appear here. Investigators might query by ServicePrincipalId or Resource to see what an app did.  
  - *Basic Query:* Retrieve recent sign-in events for a particular **application** (service principal). Suppose an app with SPN ID `abcd-1234` is suspected; you can list its logins:  
    ```kql
    // Sign-in events for a specific service principal
    AADSpnSignInEventsBeta
    | where ServicePrincipalId == "abcd-1234-efgh-5678"
    | sort by Timestamp desc
    | project Timestamp, ServicePrincipalName, ResourceDisplayName, IPAddress, ErrorCode
    ```  
    This shows when that app/service logged in, to which resource, and if it was successful (ErrorCode 0 means success). An investigator can see if the app accessed resources at odd times or from unusual IPs, indicating possible misuse.  
  - *Advanced Query:* Investigate **failed app logins** which might hint at attempted abuse. For instance, list any failed sign-in attempts for managed identities (maybe someone trying to use a managed identity token improperly):  
    ```kql
    // Failed sign-ins by managed identities
    AADSpnSignInEventsBeta
    | where IsManagedIdentity == true and ErrorCode != 0
    | project Timestamp, ServicePrincipalName, ErrorCode, IPAddress, ResourceDisplayName
    ```  
    If a managed identity had repeated failed attempts, it could indicate misconfiguration or malicious attempts to use that identity. Investigators would then check why those failures happened – perhaps someone tried to use that identity outside its intended context.

- **Threat Hunting:** Hunters may query this table to find suspicious behavior among applications. For example, an attacker who compromised an Azure AD app might use it to access data illicitly. Patterns such as an app accessing resources it normally wouldn’t, or from unusual locations, can be revealed through KQL.  
  - *Basic Query:* Hunt for **new or rarely seen service principals** logging in, which might indicate an attacker-registered app. For example, find any service principal sign-ins in the last week for apps that haven’t appeared in the prior month:  
    ```kql
    // Service principals active this week but not last month (possible new apps)
    let lastMonthSPNs = AADSpnSignInEventsBeta
        | where Timestamp between (ago(37d) .. ago(7d))
        | distinct ServicePrincipalId;
    AADSpnSignInEventsBeta
    | where Timestamp > ago(7d) and ServicePrincipalId !in (lastMonthSPNs)
    | summarize NewLogins=count() by ServicePrincipalName, ServicePrincipalId
    ```  
    This finds service principals that only started showing sign-in activity recently. A hunter would review these — especially if any correspond to generic names or unknown apps — as they might be rogue.  
  - *Advanced Query:* Look for **broad consent or multi-tenant app abuse**. For instance, if a malicious multi-tenant app has been granted access in your tenant, it might show sign-ins from unusual foreign IPs or odd resources. A complex query could flag any service principal whose login IPs span very different geographies in short time (implying token misuse). For brevity, a simpler approach: identify any app sign-ins from IPs in countries your org normally doesn’t operate in:  
    ```kql
    // App sign-ins from unusual country (e.g., not US or EU where company operates)
    AADSpnSignInEventsBeta
    | extend Country = extractcountry(IPAddress)  // assuming a function or way to map IP to country
    | where Country notin ("US","UK","DE","JP","CA")  // outside usual countries
    | summarize Events=count() by ServicePrincipalName, Country
    ```  
    If an internal app shows logins from, say, Russia or North Korea (when your business has no presence there), that’s a red flag to investigate possible key theft or malicious usage of that app.

- **Compliance Check:** Compliance here might relate to ensuring that applications authenticate in expected ways and only to approved resources. It could also mean verifying that no unauthorized third-party apps are being used. AADSpnSignInEventsBeta can be used to audit which apps are accessing what.  
  - *Basic Query:* **Audit of app usage:** list all distinct applications (service principals) that signed in over the last month, to ensure they are known/approved.  
    ```kql
    // List of service principals with sign-in activity in last 30 days
    AADSpnSignInEventsBeta
    | where Timestamp > ago(30d)
    | summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by ServicePrincipalId, ServicePrincipalName, IsManagedIdentity
    ```  
    The security/IT team can review this list against an inventory of expected apps. Any unexpected service principals (especially if not managed identities and not familiar third-party apps) can indicate shadow IT or unauthorized access, which is a compliance issue (violating change management or approval processes).  
  - *Advanced Query:* Ensure **no deprecated authentication flows** are being used by apps, aligning with security compliance (like all apps should use certificate-based auth rather than client secrets, etc.). While this table might not directly show the auth method, you might infer from certain patterns. Another compliance angle: verify that *managed identities* are used where expected instead of service principals with secrets. For example, list any sign-ins by regular service principals for Azure resources where a managed identity should be used:  
    ```kql
    // Sign-ins by non-managed service principals to Azure resource endpoints (hinting at secret-based auth)
    AADSpnSignInEventsBeta
    | where IsManagedIdentity == false and ResourceDisplayName contains "Azure"
    | summarize count() by ServicePrincipalName, ResourceDisplayName
    ```  
    If your policy says to use managed identities for Azure resources, any hit here indicates an app using client credentials (less preferred from a compliance standpoint). This can drive remediation to align with cloud security best practices.

### CloudAppEvents
**Schema Description:** The `CloudAppEvents` table contains information about **events in cloud applications and services** – specifically activities involving user accounts and objects in Office 365 and other apps integrated with Defender for Cloud Apps ([CloudAppEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table#:~:text=The%20,return%20information%20from%20this%20table)). These events can include things like file downloads from SharePoint, user sign-ins to SaaS apps, permission changes in Teams, etc. Fields cover the **action details** (ActionType, ActivityType), the **application** (Application and ApplicationId for the app, e.g. SharePoint, Exchange), **user/account info** (AccountDisplayName, AccountObjectId/UPN, plus whether the user is an admin or an external user), and context like device type, IP address with geo-info (City, CountryCode, IPAddress, etc.), as well as the objects affected (ActivityObjects might list file names or items) ([CloudAppEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table#:~:text=Column%20name%20Data%20type%20Description,order%20by%20ApplicationId%2CAppInstanceId)) ([CloudAppEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table#:~:text=and%20surname%20of%20the%20user,to%20the%20device%20during%20communication)). In short, it is a unified log of user activities across cloud apps, very useful for both security monitoring and compliance auditing of cloud resource access.

**Use Cases:**

- **Security Investigation:** If there’s suspicion of a user misusing cloud services or if an alert was triggered by some cloud activity, CloudAppEvents lets investigators see the raw events. For example, in a potential data theft incident, an investigator would look at a user’s file download or sharing events.  
  - *Basic Query:* Fetch recent activities for a specific user across Office 365 apps (like SharePoint, OneDrive, etc.) to investigate abnormal behavior. For instance:  
    ```kql
    // Last 10 cloud app events for a specific user
    CloudAppEvents
    | where AccountUpn == "bob@contoso.com"
    | sort by Timestamp desc
    | take 10
    | project Timestamp, Application, ActionType, ActivityType, ActivityObjects, IPAddress, CountryCode
    ```  
    This gives the investigator a quick view: Bob’s actions (logged in, viewed files, downloaded something, etc.), which app, what IP/location. If Bob downloaded many files from an unusual location, it will stand out here even if no alert directly flagged it.  
  - *Advanced Query:* Investigate a specific incident, e.g., a reported **mass download** from SharePoint. You could filter CloudAppEvents for a particular site or file name patterns and a user. For example, if an alert said “User X downloaded 100 files from SharePoint site Y,” verify that with:  
    ```kql
    // Filter file download events by a user from a specific SharePoint site
    CloudAppEvents
    | where Application == "SharePoint" and ActionType == "FileDownloaded"
      and AccountUpn == "userX@contoso.com"
      and ActivityObjects has "Site Y Name"
    | project Timestamp, AccountDisplayName, ActivityObjects, FileSize, IPAddress, IsAdminOperation
    ```  
    This provides evidence of the files downloaded, their size, and whether the action was done with admin privileges. Investigators can use this to confirm the scope of data accessed in the incident.

- **Threat Hunting:** CloudAppEvents is a rich source for hunting anomalous cloud usage. Hunters might search for unusual combinations of actions (e.g., a single account performing admin-like operations it never did before, or multiple file deletion events which might indicate ransomware activity on OneDrive).  
  - *Basic Query:* Hunt for **impossible travel in cloud usage** (distinct from sign-ins). For example, find cases where the same user ID has events from widely separated geolocations within a short period:  
    ```kql
    // Simple approach to find users with events in two countries on the same day
    CloudAppEvents
    | summarize Countries = makeset(CountryCode) by AccountUpn, Date = bin(Timestamp, 1d)
    | where array_length(Countries) > 1
    ```  
    If a user’s `Countries` set has, say, {"US","CN"} on the same day, that’s suspicious and similar to impossible travel (the user’s cloud activity originates from different countries on the same day). A hunter would then dive deeper into those events.  
  - *Advanced Query:* Look for potential **mass exfiltration** or data destruction. For example, identify any user who deleted or downloaded an unusually large number of files in a short period (which might not trigger a built-in alert if thresholds aren’t met):  
    ```kql
    // Users with more than 50 file deletion events in the last hour (possible mass deletion)
    CloudAppEvents
    | where ActionType == "FileDeleted" and Timestamp > ago(1h)
    | summarize Deletions=count() by AccountUpn
    | where Deletions > 50
    ```  
    Similarly, one could check for FileDownloaded > X. Such a query could catch an insider slowly exfiltrating data or a compromised account mass-deleting files (ransomware or sabotage) even if Defender didn’t raise an alert yet. The hunter can then investigate those accounts immediately.

- **Compliance Check:** CloudAppEvents can be used to verify adherence to IT and data usage policies. For example, ensure that only authorized individuals accessed certain confidential files, or that administrative actions in O365 (like mailbox exports) are tracked and done by the right people. It’s also useful for auditing (e.g., who accessed a SharePoint site).  
  - *Basic Query:* **Data access compliance:** List any access to sensitive files or sites by users outside a permitted group. If you tag sensitive files or know naming conventions (e.g., files containing "HR-confidential"), you can check if anyone outside HR accessed them:  
    ```kql
    // Potential unauthorized access to HR confidential files
    CloudAppEvents
    | where ActionType == "FileAccessed" and ActivityObjects has "HR-Confidential"
    | summarize count() by AccountUpn, ActionType
    ```  
    If an account from, say, Marketing shows up here accessing HR confidential files, that’s a compliance issue to investigate (possible permission creep or misuse).  
  - *Advanced Query:* **Administrative operations audit:** Ensure only admins perform admin-level operations. For example, verify that all Exchange mailbox export events (if those are logged via CloudAppEvents under an appropriate ActionType) were done by accounts with admin roles. You might do:  
    ```kql
    // Audit if any non-admin performed admin operations
    CloudAppEvents
    | where IsAdminOperation == false and ActionType in ("AddedMailboxPermission","ResetUserPassword","ChangedOrgSetting")
    | summarize Events=count() by AccountDisplayName, ActionType
    ```  
    *(In this hypothetical query, replace ActionType filters with actual admin actions logged.)* If any user without admin privileges (IsAdminOperation == false) attempted or performed an admin-like action, that’s non-compliant. The security team would need to check how that happened (was a role misassigned? a bug? a malicious attempt that somehow succeeded?). This helps ensure that privilege boundaries in cloud apps are respected and quickly flags violations for correction.

### IdentityInfo
**Schema Description:** The `IdentityInfo` table provides information about user accounts gathered from various sources (like Azure AD/Microsoft Entra and on-prem AD) ([IdentityInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table#:~:text=The%20,return%20information%20from%20this%20table)). It is essentially an **inventory of identity details** – each record is an identity (user) and includes attributes such as the account’s **display name, UPN, Azure AD ObjectId, on-prem AD SID** (if synced), and directory information like **department, job title, email, city, country**, etc. ([IdentityInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table#:~:text=%60ReportId%60%20,User%20name%20of%20the%20account)) ([IdentityInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table#:~:text=,Address%20of%20the%20account%20user)). This table is great for enriching other data (mapping user IDs to friendly names or organizational info) and for compliance or threat hunting by user attributes (e.g., find all accounts in a certain department or with certain properties). It was formerly known as *AccountInfo*.

**Use Cases:**

- **Security Investigation:** Investigators often use IdentityInfo to get background on a user involved in an incident. For example, if an alert involves user `alice@contoso.com`, the investigator can quickly pull Alice’s department, job role, whether her account is enabled, etc., to assess impact or insider threat potential.  
  - *Basic Query:* Get the identity details for a specific user (by UPN or account object ID):  
    ```kql
    // Fetch identity information for a specific user
    IdentityInfo
    | where AccountUpn == "alice@contoso.com"
    ```  
    This returns Alice’s full profile: name, email, department, title, whether the account is enabled (`IsAccountEnabled`), etc. Knowing her role (say she’s in Finance and the alert was about finance data access) can help determine if the activity was expected or not.  
  - *Advanced Query:* Enrich an investigation involving multiple accounts. For example, if multiple user IDs were found in a log or alert, you could join those IDs with IdentityInfo to list their departments and job titles in one go, to see if there’s a pattern (maybe all from same department or all new hires):  
    ```kql
    // Enrich a list of suspicious AccountObjectIds with identity details
    let suspiciousUsers = datatable(AccountObjectId:string)["<ID1>", "<ID2>", "<ID3>"];
    suspiciousUsers
    | join IdentityInfo on AccountObjectId
    | project AccountDisplayName, AccountUpn, Department, JobTitle, IsAccountEnabled
    ```  
    This would output, for example, that ID1 is Alice – Finance Analyst, ID2 is Bob – Sales Rep, etc., allowing the investigator to assess why these users were targeted or involved. If all are from one team, maybe that team’s data was targeted.

- **Threat Hunting:** Hunters can query IdentityInfo to find accounts that meet certain criteria that might pose a risk. For example, *stale accounts* (enabled accounts that haven’t been used, or with no recent logon events), or *high-privileged accounts* for focused monitoring. While IdentityInfo doesn’t directly label privileged accounts, one could hunt by job title or group membership if synchronized (though group info might not be directly in this table, Sentinel’s UEBA might have something similar).  
  - *Basic Query:* Find **disabled accounts** or accounts marked as *not enabled* in Azure AD that still show up in logs (possibly indicating use of a disabled account). First, just identify disabled accounts:  
    ```kql
    // List disabled user accounts (IsAccountEnabled = false)
    IdentityInfo
    | where IsAccountEnabled == false
    | project AccountDisplayName, AccountUpn, Department, LastUpdated=Timestamp
    ```  
    A threat hunter might then cross-reference these with sign-in logs (if a disabled account is logging in, that’s a big issue). This basic query itself is also useful for compliance (ensuring leavers’ accounts are indeed disabled).  
  - *Advanced Query:* **Shadow admin hunting** – find accounts that are not obviously admins by title or department, but are members of privileged groups. If on-prem AD group memberships were pulled into IdentityInfo’s properties (not sure if **NodeProperties** from ExposureGraphNodes might be needed for that), a complex approach would join IdentityInfo with ExposureGraphEdges/Nodes for group membership. For example, find any account whose `JobTitle` does *not* contain "Admin" but is a member of a domain admins group (this might require using ExposureGraphEdges for group relationships, or if not available, perhaps a custom list of known admins by UPN). A simpler heuristic: find accounts with *password never expires* or other flags if present (not sure if IdentityInfo includes such flags; likely not directly). If not, one can use role keywords:  
    ```kql
    // Identify accounts with admin-sounding roles
    IdentityInfo
    | where JobTitle contains "Admin" or Department contains "IT"
    ```  
    (This is a weak proxy; better to correlate with directory group info via other tables if possible.) The idea is to then focus threat hunting on those accounts in other logs (like see if any of these admin accounts had risky logins). Even without direct correlation here, a hunter could generate a list of high-value accounts from IdentityInfo and use it in queries on sign-in or device logs.

- **Compliance Check:** IdentityInfo is very useful for compliance and audit scenarios: ensuring that user account details meet certain standards (like everyone has a department and manager filled in), checking accounts that should be disabled (e.g., last day was 30 days ago, but still enabled), or listing accounts by region for data residency compliance.  
  - *Basic Query:* **Orphaned account check:** Identify accounts that might have left the organization but are still enabled. If IdentityInfo updates when an account is detected as changed or every 24h, one approach is to cross-check a list of known leavers or use the absence of recent activity. For instance, find enabled accounts that haven’t had a logon in 60 days (requires join with IdentityLogonEvents or using a last logon timestamp if available in IdentityInfo, which it isn’t directly). As a simplified compliance query: list all accounts that are enabled (`IsAccountEnabled == true`) but have no department or title (could indicate service accounts or improperly managed accounts):  
    ```kql
    // Enabled accounts missing department or title info
    IdentityInfo
    | where IsAccountEnabled == true and (isempty(Department) or isempty(JobTitle))
    | project AccountDisplayName, AccountUpn, Department, JobTitle
    ```  
    Such accounts might violate HR/IT policy for account metadata completeness, or could be service accounts (which then should be reviewed for proper handling or MFA enforcement).  
  - *Advanced Query:* **Role-based compliance:** Ensure that privileged accounts (like global admins) have certain attributes set (like multi-factor authentication enforced or a manager assigned). This might require correlating with an external list of admin accounts. Suppose you have a list of admin AccountObjectIds (`adminList`) from Azure AD roles; you could verify those accounts in IdentityInfo have MFA (not a field here) or at least see if they belong to the IT department and have appropriate titles:  
    ```kql
    // Cross-check that all tenant admins are in IT department
    let tenantAdmins = datatable(AccountObjectId:string)["<AdminID1>", "<AdminID2>"];
    tenantAdmins
    | join IdentityInfo on AccountObjectId
    | project AccountDisplayName, Department, JobTitle, IsAccountEnabled
    | where Department !contains "IT"
    ```  
    This would flag if any of your global admins are not listed under IT (which might be against policy, since only IT staff should have admin roles). Similarly, you could check if `IsAccountEnabled` is true for all (if any admin account is disabled, why does it still have a role?) etc. This kind of query helps ensure alignment between HR role, IT role, and technical privileges – a key compliance aspect in least privilege and account management.

### IdentityLogonEvents
**Schema Description:** The `IdentityLogonEvents` table logs **authentication events** from two realms: on-premises Active Directory (via Defender for Identity) and Microsoft online services (via Defender for Cloud Apps) ([IdentityLogonEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table#:~:text=The%20,return%20information%20from%20this%20table)). It covers interactive logons, RDP, NTLM authentications, Kerberos, as well as cloud sign-ins (particularly those not in AADSignInEventsBeta). Key fields include **ActionType** (the kind of logon activity), **LogonType** (interactive, remote, network, etc. for Windows logons ([DeviceLogonEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table#:~:text=,Type%20of%20logon%20session%2C%20specifically))), **Protocol** (Kerberos, NTLM, OAuth, etc.), **Account** details (name, UPN, SID, objectId), and device info (DeviceName, DeviceType, OS platform) ([IdentityLogonEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table#:~:text=Supported%20logon%20types.%20,account%20in%20Microsoft%20Entra%20ID)) ([IdentityLogonEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table#:~:text=book,Windows%2010%20and%20Windows%207)). Essentially, this is the unified logon table combining signals from on-prem AD and cloud, allowing holistic identity authentication hunting.

**Use Cases:**

- **Security Investigation:** When investigating identity-related incidents (like possible lateral movement or brute force on AD, or suspicious cloud logins), IdentityLogonEvents is the go-to. For example, if a user’s account was potentially compromised, an investigator will pull all logon events for that user around the time in question (both on-prem AD logons and cloud sign-ins that fall into this table).  
  - *Basic Query:* Get recent logon events for a specific user to see if there were failures, from where, and what type (e.g., Kerberos vs. cloud OAuth). For instance:  
    ```kql
    // Last 5 logon events (on-prem or cloud) for user jdoe
    IdentityLogonEvents
    | where AccountUpn == "jdoe@contoso.com" 
    | sort by Timestamp desc
    | take 5
    | project Timestamp, ActionType, LogonType, Protocol, DeviceName, FailureReason
    ```  
    This might show, for example, John Doe had an NTLM login failure on a server, followed by a successful cloud login from an unfamiliar device. The investigator can use this timeline to trace suspicious behavior (like an attacker moving from cloud to on-prem).  
  - *Advanced Query:* Investigate **lateral movement**: For instance, if an alert indicates a certain user logged onto multiple machines (pass-the-hash scenario), query for that user’s distinct DeviceNames in a short timeframe:  
    ```kql
    // Check if a user logged into multiple devices in 1 hour (possible lateral movement)
    IdentityLogonEvents
    | where AccountName == "ADMINISTRATOR" and Timestamp between (ago(1h) .. now())
    | summarize UniqueDevices=dcount(DeviceName), Devices=make_set(DeviceName)
    ```  
    If *ADMINISTRATOR* (or any account of interest) shows logons on multiple devices in the same hour, that’s a red flag (unless expected). Investigators would then focus on those devices for further evidence of compromise.

- **Threat Hunting:** With IdentityLogonEvents, hunters can look for patterns like **brute force attacks, anomalous logon times, use of legacy protocols** in AD, or unusual logon types (like a service account doing interactive login, which shouldn’t happen). The combination of on-prem and cloud auth data allows detection of patterns spanning both (e.g., an attacker using a compromised account both in AD and in O365).  
  - *Basic Query:* Hunt for **failed logon streaks** on on-prem AD (a likely brute force). For example, find any account with a high number of failed authentication events (ActionType might include “LogonFailed” or FailureReason not null) within a short period:  
    ```kql
    // Accounts with >20 failed logons in last 30 minutes (possible brute force)
    IdentityLogonEvents
    | where Timestamp > ago(30m) and isnotempty(FailureReason)
    | summarize FailedCount=count() by AccountUpn
    | where FailedCount > 20
    ```  
    This spots accounts under password guessing attacks. A hunter who finds such accounts will then check if any succeeded or if the same source is hitting many accounts.  
  - *Advanced Query:* Look for **suspicious logon types** – e.g., a LogonType that is unusual for certain accounts. If service accounts should never log on interactively, but one did, that’s a sign. For example:  
    ```kql
    // Service accounts (by name pattern) doing interactive or RDP logons
    IdentityLogonEvents
    | where AccountName startswith "svc_" and LogonType in ("Interactive", "RemoteInteractive")
    | project Timestamp, AccountName, DeviceName, LogonType
    ```  
    If a service account (often prefixed `svc_` or similar) logged on interactively or via RDP, it could indicate that an attacker is using those credentials to pivot, since normally those accounts are used only for running services, not logging in. This helps hunt down potential misuse of high-privilege service accounts.

- **Compliance Check:** From a compliance perspective, IdentityLogonEvents can help ensure that authentication policies are followed: e.g., no NTLM where not allowed, no logons outside business hours for certain sensitive systems (depending on policy), or that all admin logons are audited. It’s also useful for detecting accounts that might violate access policies (like logging in from an unauthorized network).  
  - *Basic Query:* **Legacy auth usage:** Many organizations aim to eliminate NTLM authentication due to security and compliance reasons. You can check if NTLM (an older protocol) is still being used in logons:  
    ```kql
    // Count of NTLM vs Kerberos logons in last 24h (on-prem AD)
    IdentityLogonEvents
    | where Timestamp > ago(24h) and Protocol in ("NTLM","Kerberos")
    | summarize Count=count() by Protocol
    ```  
    If NTLM count is significant, you have non-compliance with a possible policy to prefer Kerberos/modern auth. You could drill down further by device or account to pinpoint where NTLM is happening (maybe an outdated system or an application using it).  
  - *Advanced Query:* Ensure that **privileged accounts** log on only in approved ways. For instance, domain admins should maybe only log on to domain controllers or jump boxes. You can verify if a highly privileged account logged on to a regular workstation, which might be against policy. If you have a list of privileged accounts (by group membership or naming), use that:  
    ```kql
    // Check if any Domain Admins logged onto non-domain-controller machines
    let domainAdmins = pack_array("DAlice", "DBob");  // list of domain admin account names
    IdentityLogonEvents
    | where AccountName in (domainAdmins) and DeviceType != "DomainController" and LogonType == "Interactive"
    | project Timestamp, AccountName, DeviceName, LogonType
    ```  
    Any result here means a Domain Admin (DAlice or DBob) logged on interactively to a machine that is not a DC, which many security policies forbid due to risk. This compliance query helps flag risky behavior for further training or enforcement (like reminding admins to use jump servers). Another compliance check could be to detect interactive logons by accounts that are supposed to be *service accounts only* (we did a variant in threat hunting). 

### EmailAttachmentInfo
**Schema Description:** The `EmailAttachmentInfo` table contains information about **files attached to emails** that were processed by Defender for Office 365 (Exchange Online Protection) ([EmailAttachmentInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table#:~:text=The%20,return%20information%20from%20this%20table)). Each record represents an attachment on an email message, including fields such as the parent email’s identifiers (**NetworkMessageId** and InternetMessageId), sender/recipient info, and details of the attachment file: **FileName**, **FileType** (extension), file **SHA256 hash**, file size, and any threat assessment results (e.g., **ThreatTypes** indicating if malware was detected, **ThreatNames** for malware family, **DetectionMethods** used) ([EmailAttachmentInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table#:~:text=,account%20in%20Microsoft%20Entra%20ID)) ([EmailAttachmentInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table#:~:text=Microsoft%20Entra%20ID%20,malware%20or%20other%20threats%20found)). This table is typically used in conjunction with EmailEvents (which logs the email itself) to investigate malicious attachments or track a specific file in mail flow.

**Use Cases:**

- **Security Investigation:** When an alert or incident involves a malicious email attachment (e.g., a malware-infected document), investigators use EmailAttachmentInfo to get details on that file and to trace where else it might have appeared. For instance, if a particular attachment hash is known to be malicious, they’ll search this table for that hash to find all users who received it.  
  - *Basic Query:* Find all instances of a suspicious file (by hash or name) in emails. Suppose you have a SHA256 for a malware attachment, you can query:  
    ```kql
    // Find emails carrying a specific malicious file (by SHA256)
    EmailAttachmentInfo
    | where SHA256 == "<malicious-file-hash>"
    | project Timestamp, FileName, SenderFromAddress, RecipientEmailAddress, ThreatTypes
    ```  
    This shows when and between whom that file was sent, and whether it was flagged (ThreatTypes might show "Malware" if it was detected). It helps scope an incident (did only one person get it or many?).  
  - *Advanced Query:* Investigate a phishing campaign by correlating attachments with the emails. For example, list all recipients who got an email with a known bad attachment and whether they clicked it (would require joining with UrlClickEvents or other data, but within attachment info you can at least get recipients and whether it was blocked). Another angle: sometimes multiple attachments in different emails have the same ThreatName (malware family). You could gather all attachment hashes labeled as a certain malware:  
    ```kql
    // Find all attachment hashes associated with a specific malware family
    EmailAttachmentInfo
    | where ThreatNames has "Trickbot"  // example malware name
    | summarize CountEmails=dcount(NetworkMessageId), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by SHA256, FileName, ThreatNames
    ```  
    This gives a set of file hashes identified as Trickbot in emails, how many messages they were found in, and the timeframe. Investigators can then cross-check if those files were executed on endpoints (DeviceFileEvents) or ensure they were blocked.

- **Threat Hunting:** Hunters might use EmailAttachmentInfo to search for patterns of potentially malicious attachments that slipped past detection or to identify how new threat campaigns might be manifesting in email. For example, hunting for unusual file types being sent or attachments with suspicious names.  
  - *Basic Query:* Find **executable attachments** being sent via email – since .exe, .scr, etc., are rarely sent in legitimate business communications, their presence could indicate malicious activity or policy violations. For instance:  
    ```kql
    // Look for executables or script files in email attachments (last 7 days)
    EmailAttachmentInfo
    | where Timestamp > ago(7d) and FileType in~ (".exe", ".dll", ".js", ".scr", ".bat")
    | project Timestamp, FileName, SenderFromAddress, RecipientEmailAddress, ThreatTypes
    ```  
    Even if ThreatTypes is empty (meaning not flagged as malware), a list of emails with .exe attachments is worth reviewing. The hunter might find a .exe that was not detected as malware (zero-day) and proactively investigate it.  
  - *Advanced Query:* Hunt for **bulk suspicious attachments** – e.g., the same attachment name sent to many recipients (could be a phishing with common lure file). Using KQL to identify top FileName that was sent to many distinct recipients:  
    ```kql
    // Potential mass phishing: attachments with many distinct recipients
    EmailAttachmentInfo
    | where Timestamp > ago(2d)
    | summarize RecipCount=dcount(RecipientEmailAddress) by FileName, SHA256, ThreatTypes
    | where RecipCount > 10 and isempty(ThreatTypes)  // not flagged by AV, but mass-sent
    ```  
    This surfaces files that were widely distributed but not necessarily caught by filters. If an attachment shows up in 50 mailboxes and wasn’t flagged, a threat hunter would certainly investigate that file’s nature (it could be an emerging threat).

- **Compliance Check:** From a compliance or policy perspective, one might use EmailAttachmentInfo to ensure that certain types of files aren’t being sent via email (like executables or classified docs) or that DLP policies are effective. It can also be used to track large file movements via email.  
  - *Basic Query:* **Restricted file types** – If company policy forbids sending certain file types via email (e.g., .pst files or password-protected zips), you could query for those. For example:  
    ```kql
    // Check if any .pst files were sent as attachments (policy violation)
    EmailAttachmentInfo
    | where FileType == ".pst"
    | summarize TotalSent = count(), UniqueSenders=dcount(SenderFromAddress)
    ```  
    If this returns any, it means mailbox archives were sent via email, which might breach data management policies. Similarly, you could search for *.zip* and some indicator of encryption (though detection of encrypted files may be in ThreatTypes or detection methods if available).  
  - *Advanced Query:* **Data leakage auditing** – e.g., find if any sensitive document (perhaps by keyword in filename or by classification label if those propagate to the attachment info) was sent outside the organization. If `RecipientEmailAddress` not ending in your domain indicates external recipient, you can combine that logic:  
    ```kql
    // Possible data leak: confidential files sent to external recipients
    EmailAttachmentInfo
    | where FileName contains "Confidential" or FileName contains "Sensitive"
    | extend IsExternalRecipient = iff(RecipientEmailAddress !endswith "@contoso.com", "Yes", "No")
    | summarize Attachments=count() by FileName, Sender=SenderFromAddress, IsExternalRecipient
    | where IsExternalRecipient == "Yes"
    ```  
    This finds attachments with "Confidential" in the name that went to anyone outside contoso.com. Each such occurrence could be a compliance issue (if not sanctioned), and you’d likely cross-check if DLP caught it or not. Even without explicit labels, looking at *IsExternalRecipient == Yes* for large or suspicious file names can help compliance teams catch mistakes or malicious exfiltration via email.

### EmailEvents
**Schema Description:** The `EmailEvents` table logs **Microsoft 365 email events**, covering the journey and filtering of each email message ([EmailEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table#:~:text=The%20,return%20information%20from%20this%20table)). Each record typically represents an email and includes details like **NetworkMessageId** (internal unique ID for the email), **InternetMessageId** (SMTP Message-ID), sender and recipient addresses, subject, and what happened to the email (delivery status, spam/phish verdicts as part of ActionType). It also logs **EmailDirection** (Inbound, Outbound) and various source/destination info, plus fields like **DeliveryLocation** or **ThreatTypes** if any were detected. Essentially, this table is used to trace email flow (delivered, blocked, dropped, etc.) and analyze email metadata.

**Use Cases:**

- **Security Investigation:** When investigating a phishing incident, EmailEvents is used to find the email that delivered the phish: who sent it, who received it, when, and what was done (was it delivered or filtered). Analysts also use it to retrieve the subject and network message ID to correlate with attachments and URL data.  
  - *Basic Query:* Find a specific email by subject or by sender/recipient. For example, if an executive reported a suspicious email with subject "Invoice", an investigator can search:  
    ```kql
    // Search for emails with a specific subject
    EmailEvents
    | where Subject has "Invoice" and RecipientEmailAddress == "ceo@contoso.com"
    | project Timestamp, SenderFromAddress, RecipientEmailAddress, DeliveryLocation, EmailDirection
    ```  
    This shows if the CEO received any invoice-related emails, from whom, and whether they landed in Inbox or were filtered (DeliveryLocation might say Inbox, Junk, Quarantine, etc.). This helps confirm if the reported email exists and its path.  
  - *Advanced Query:* Trace a phishing campaign by finding all emails with the same characteristics. If one malicious email is found, use its NetworkMessageId or InternetMessageId as an identifier to find related messages (sometimes multiple recipients cause multiple NetworkMessageIds with same InternetMessageId if it’s the same email). For instance:  
    ```kql
    // Get all recipients of a phishing email by InternetMessageId
    let phishId = EmailEvents
                  | where Subject == "[Payment Notice]" and SenderFromDomain == "evil.com"
                  | project InternetMessageId
                  | take 1;
    EmailEvents
    | where InternetMessageId in (phishId)
    | project Timestamp, SenderFromAddress, RecipientEmailAddress, DeliveryLocation, ThreatTypes
    ```  
    This finds all instances of that email (maybe sent to many people). Investigators can then see who else got it and if it was blocked (ThreatTypes might indicate if it was marked as phishing or not). If some got through (Inbox), those users need immediate action (like forcible quarantine via ZAP or user education).

- **Threat Hunting:** Hunters query EmailEvents to uncover malicious patterns that might not have triggered an alert. For example, a sudden surge in emails from a new domain, or many emails with suspicious keywords, or unusual senders for internal users.  
  - *Basic Query:* Hunt for **mass mail-outs** from one internal account (could indicate a compromised account sending spam internally). For instance, find if any internal sender sent email to an unusually high number of recipients in a short time:  
    ```kql
    // Internal accounts sending to many recipients (possible compromised account spamming)
    EmailEvents
    | where EmailDirection == "Outbound" and SenderFromDomain == "contoso.com"
    | summarize RecipCount=dcount(RecipientEmailAddress), LastSeen=max(Timestamp) by SenderFromAddress
    | where RecipCount > 50
    ```  
    If an internal user account is found sending to 50+ distinct recipients recently, that’s suspicious (especially if they don’t normally do that). A threat hunter would investigate that account for compromise.  
  - *Advanced Query:* Identify **targeted phishing** by looking for certain keywords in subjects among inbound emails that were delivered (i.e., might have bypassed filters). For example:  
    ```kql
    // Potential phishing: look for delivered emails with common phishing subject keywords and no detection
    EmailEvents
    | where EmailDirection == "Inbound" and DeliveryLocation == "Inbox"
      and Subject matches regex @"(?i)urgent|password|verify|action required"
      and isempty(ThreatTypes)
    | project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress
    ```  
    This picks up emails that contain typical phishing lingo in the subject ("urgent", "action required", etc.), that landed in inbox without being classified as malware/phish (ThreatTypes empty). A hunter can review these subjects and senders – they may find a phishing attempt that EOP missed due to being low-volume or cleverly crafted. It’s a way to catch what automated filters might have missed.

- **Compliance Check:** EmailEvents can help in compliance scenarios like ensuring email usage policies are followed (e.g., no auto-forwarding to personal accounts, no mass mailing of sensitive info, etc.), and to gather metrics for compliance reports (like number of emails encrypted, or how many were blocked as spam which might relate to anti-spam compliance).  
  - *Basic Query:* **External forwarding check:** Many organizations disallow auto-forwarding of corporate email to external addresses for data protection. To verify compliance, one could check if any user is sending a high volume of mail to the same external address (which might indicate a forward or manual exfiltration). For example, count how many emails each internal user sent to *@gmail.com addresses:  
    ```kql
    // Detect potential auto-forwarding: internal to external patterns
    EmailEvents
    | where EmailDirection == "Outbound" and RecipientEmailAddress !endswith "@contoso.com"
    | summarize ExternalEmails=count() by SenderFromAddress, RecipientDomain = tostring(split(RecipientEmailAddress, "@")[1])
    | where ExternalEmails > 100 and RecipientDomain endswith "gmail.com"
    ```  
    This might show that bob@contoso.com sent 300 emails to gmail.com addresses – possibly auto-forwarding to a personal account. Compliance can then investigate if that’s an approved exception or a violation.  
  - *Advanced Query:* **Encryption/Confidentiality compliance:** If using O365 Message Encryption or sensitivity labels, one might want to ensure that sensitive info sent out is always encrypted. While EmailEvents might not directly show if a mail was encrypted, it could show if a sensitivity label or certain header was applied. Alternatively, check if emails marked with a certain classification (if that populates ThreatTypes or other fields) were sent in clear. Without that, another approach: ensure that all emails with certain keywords (like "SSN" or "Confidential") were caught by DLP (which might appear as ActionType indicating a DLP rule or in EmailEvents possibly not, might need the DLP events via CloudAppEvents if integrated). A simplistic check:  
    ```kql
    // Check if any email with 'Confidential' in subject/body was sent unencrypted externally
    EmailEvents
    | where EmailDirection == "Outbound" and DeliveryLocation == "Delivered"
      and (Subject has "Confidential" or Subject has "Sensitive")
      and RecipientEmailAddress !endswith "@contoso.com"
      and isempty(ThreatTypes)  // not blocked or modified by DLP (assuming it'd tag as threat if so)
    ```  
    This is not a definitive method, but if it yields results, compliance might need to review those emails to ensure no sensitive info leaked. A more direct compliance query could be to list all emails that were blocked by DLP (if DLP events surface as ThreatTypes or a specific ActionType like "DLPBlock" – those might be logged in EmailEvents or perhaps EmailPostDeliveryEvents if removed after delivery). For example, count how many emails were blocked due to sensitive info to report compliance with data protection policies.

### EmailPostDeliveryEvents
**Schema Description:** The `EmailPostDeliveryEvents` table logs **security-related actions on emails after they have been delivered** to mailboxes ([EmailPostDeliveryEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailpostdeliveryevents-table#:~:text=The%20,return%20information%20from%20this%20table)). This includes things like automated remediation (e.g., **ZAP** – Zero-hour Auto Purge removing a phishing email from Inbox after initial delivery), manual remedial actions (admin removing or releasing from quarantine), or user actions (like user report phish). Key fields include the email identifiers (NetworkMessageId, InternetMessageId), the **Action** taken (e.g., MovedToJunk, Deleted, ReleasedFromQuarantine), **ActionType** (what triggered it: e.g., Phish ZAP, Malware ZAP, Manual remediation) ([EmailPostDeliveryEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailpostdeliveryevents-table#:~:text=,recipient%20after%20distribution%20list%20expansion)), who triggered it (**ActionTrigger** – admin vs system), and the result of the action ([EmailPostDeliveryEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailpostdeliveryevents-table#:~:text=,recipient%20after%20distribution%20list%20expansion)). Essentially, this table is used to see what happened to an email *after* delivery, especially if it was later flagged as malicious or moved.

**Use Cases:**

- **Security Investigation:** If an email was delivered and later removed by the system (or an admin), investigators will look at EmailPostDeliveryEvents to understand that timeline. For instance, after a user reports a phishing email, an admin might run a script to delete it from all mailboxes – that action would show up here. This helps confirm whether a malicious email was contained.  
  - *Basic Query:* Check if a particular email (by NetworkMessageId or subject) was removed by ZAP or other means. For example, if investigating a phishing email with known NetworkMessageId:  
    ```kql
    // Check post-delivery actions for a specific email
    EmailPostDeliveryEvents
    | where NetworkMessageId == "<message-id-guid>"
    | project Timestamp, Action, ActionType, ActionTrigger, RecipientEmailAddress, ActionResult
    ```  
    This reveals, say, that at a certain time, the email was `MovedToDeletedItems` by `Phish ZAP` automatically, result `Succeeded`. The investigator thus knows the email was initially delivered but then ZAP took it out of user inboxes.  
  - *Advanced Query:* See how widespread a ZAP action was – e.g., if a phish was removed, list all recipients that had it removed. You can join with EmailEvents to get subject or sender if needed. For instance:  
    ```kql
    // List recipients of a ZAPped phishing email (by InternetMessageId)
    let zapMsg = EmailPostDeliveryEvents
                | where ActionType == "Phish ZAP"
                | project InternetMessageId, NetworkMessageId;
    zapMsg
    | join (EmailEvents | project InternetMessageId, Subject, SenderFromAddress) on InternetMessageId
    | join kind=inner (EmailPostDeliveryEvents | where ActionType == "Phish ZAP") on InternetMessageId
    | project Timestamp, Subject, SenderFromAddress, AffectedRecipient=RecipientEmailAddress, ActionResult
    ```  
    This yields the list of recipients whose emails got ZAPped (since EmailEvents might show multiple NetworkMessageIds for the same InternetMessageId if sent separately). It confirms the scope – investigators ensure all copies were addressed.

- **Threat Hunting:** Hunters might examine EmailPostDeliveryEvents for patterns of post-delivery cleanup, which could indicate missed phish that were later caught. For example, frequent Phish ZAP actions might reveal that some phish are getting through initial filters. They might also hunt for any **user reports** (if user report is logged here, possibly as an Action like "UserReported", ActionTrigger = user).  
  - *Basic Query:* Hunt for **trends in ZAP** – e.g., how many phishing ZAPs happened in the last week, which might indicate volume of phish getting through initially.  
    ```kql
    // Count of Phish ZAP actions by day (last 7 days)
    EmailPostDeliveryEvents
    | where Timestamp > ago(7d) and ActionType == "Phish ZAP"
    | summarize ZAPs=count() by bin(Timestamp, 1d)
    ```  
    A hunter sees if there's a spike on a particular day, meaning a campaign slipped through and then got mass-removed. They might then pivot to what those emails were (joining EmailEvents as shown above) to analyze the campaign characteristics and improve filtering.  
  - *Advanced Query:* Identify if **any malicious emails might have evaded even ZAP.** One heuristic: look for user reports of phish *without* corresponding ZAP actions. If users reported but system didn't auto-remove, that could be a gap. If user reporting is logged (it might show Action="UserReported" or similar in this table or another audit log), one could do:  
    ```kql
    // User reported phish that were not ZAPped
    let reported = EmailPostDeliveryEvents
                   | where Action == "UserReported" or ActionTrigger == "User"
                   | project NetworkMessageId, ReportTime = Timestamp;
    let zapped = EmailPostDeliveryEvents
                 | where ActionType contains "ZAP"
                 | distinct NetworkMessageId;
    reported
    | where NetworkMessageId !in (zapped)
    | join (EmailEvents | project NetworkMessageId, SenderFromAddress, Subject) on NetworkMessageId
    | project ReportTime, Subject, SenderFromAddress, ReportedBy = RecipientEmailAddress
    ```  
    This query finds emails that a user reported as phishing but that were never ZAPped (meaning the system didn’t automatically remove them). These could be missed phish; a threat hunter would review these emails to see why filters missed them and perhaps add blocks or raise awareness.

- **Compliance Check:** From a compliance perspective, EmailPostDeliveryEvents can verify that certain procedures happened. For example, ensuring that all malicious emails were cleaned up (no stragglers left unremoved), or documenting the response to phishing for audit. It can also help demonstrate that the organization’s DLP or threat response policies (like removing bad emails within X hours) are being enforced.  
  - *Basic Query:* **Verification of removal:** If policy says all confirmed phishing emails must be removed from mailboxes, check if any known phishing emails (perhaps by presence in EmailEvents with ThreatTypes "Phish") did *not* have a corresponding removal action. A simple check: ensure that any email marked as phish was indeed moved or deleted (Action could be Phish ZAP or moved to quarantine). For instance:  
    ```kql
    // Verify every phish verdict email had a post-delivery action
    let phishEmails = EmailEvents | where ThreatTypes has "Phish" | distinct NetworkMessageId;
    phishEmails
    | join kind=leftanti (EmailPostDeliveryEvents | distinct NetworkMessageId) on NetworkMessageId
    ```  
    If this returns any NetworkMessageId, it means an email flagged as phish in EmailEvents did not show up in post-delivery actions (maybe it was blocked pre-delivery, or worst case, delivered and not removed). Compliance would want to ensure none were delivered without later action. If results are found, those need review to see if an action was missed.  
  - *Advanced Query:* **Quarantine release audit:** If policy restricts releasing quarantined emails (e.g., only admins can, or it requires justification), use this table to audit releases. For example, list all emails that were released from quarantine and by whom (ActionTrigger might indicate admin).  
    ```kql
    // Audit of released-from-quarantine emails
    EmailPostDeliveryEvents
    | where Action == "MessageReleased" or Action has "Released"
    | project Timestamp, ReleasedBy=ActionTrigger, Recipient=RecipientEmailAddress, ActionResult
    ```  
    This shows when and how quarantined emails got released. If ReleasedBy indicates an admin action, compliance can cross-verify if proper approvals were in place. If it shows "User" (if allowed), compliance might flag it if policy says users shouldn’t release their own quarantined mail. Essentially, it’s checking that quarantine release controls are followed. This can be extended by joining EmailEvents to know what the email was (subject, sender) for reporting.

### EmailUrlInfo
**Schema Description:** The `EmailUrlInfo` table contains information about **URLs found in emails and attachments** processed by Defender for Office 365 ([EmailUrlInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table#:~:text=The%20,return%20information%20from%20this%20table)). Each record represents a URL that was extracted from an email (either in the body, subject, or even inside an attachment like a PDF with a link). Key fields include the **NetworkMessageId** (linking it to the specific email), the full **Url**, the **UrlDomain** (host part of the URL), and **UrlLocation** indicating where in the email the URL was found (e.g., Body, Headers, Attachment, or even “QRCode” if it came from a scanned QR code image ([EmailUrlInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table#:~:text=,the%20DeviceName%20and%20Timestamp%20columns)) ([EmailUrlInfo table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table#:~:text=To%20hunt%20for%20attacks%20based,URLs%20extracted%20from%20QR%20codes))). This table is especially useful for phishing investigations to identify malicious links in emails and pivot on those across multiple messages.

**Use Cases:**

- **Security Investigation:** If a phishing email is suspected, investigators will extract any URLs from it to see where they point (and if they are known malicious). EmailUrlInfo provides those links without needing to manually parse the email. For example, if a user clicked a link, you’d want to know what that link was. By using the NetworkMessageId from the user’s email (via EmailEvents or UrlClickEvents), you can get the URL.  
  - *Basic Query:* Given a particular email’s NetworkMessageId (or known subject/sender to filter), retrieve all URLs present in that email:  
    ```kql
    // Get URLs from a specific email by subject
    let msg = EmailEvents 
             | where Subject == "Action Required: Update Account"
             | project NetworkMessageId;
    EmailUrlInfo
    | where NetworkMessageId in (msg)
    | project Url, UrlDomain, UrlLocation
    ```  
    This would list something like `http://contoso-updates.com/verify` domain `contoso-updates.com` in body, etc. Investigators can then check these domains against threat intel or see if they appear in other emails.  
  - *Advanced Query:* Determine if the same phishing URL was sent to multiple people. For instance, take a known bad URL domain from one phishing email and find all emails containing URLs from that domain:  
    ```kql
    // Find all emails that contained URLs from a suspicious domain
    EmailUrlInfo
    | where UrlDomain == "contoso-updates.com"
    | join EmailEvents on NetworkMessageId
    | project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url
    ```  
    This correlates URL info with the email details. It helps an investigator see the scope of a phishing campaign using that fake domain. If 10 people got emails with that link, all need to be warned or the emails removed.

- **Threat Hunting:** Hunters can use EmailUrlInfo to search for **patterns in URLs** that might indicate phishing or other malicious intent. For example, domains that are newly seen, or URLs with certain suspicious strings (like “login” or “verify” plus a non-official domain), or even any occurrence of IP addresses as URLs (often a bad sign).  
  - *Basic Query:* Hunt for **URLs in emails that are plain IP addresses** (e.g., `http://123.456...` which is often suspicious).  
    ```kql
    // Find email URLs that use bare IP addresses (possible malicious)
    EmailUrlInfo
    | where Url matches regex @"http[s]?://\d+\.\d+\.\d+\.\d+"
    | summarize CountEmails=dcount(NetworkMessageId) by Url
    ```  
    If such URLs appear, likely someone sent an email with a direct IP link (which is rare in legitimate email). A hunter would examine those (maybe they point to a malware download).  
  - *Advanced Query:* Look for **typosquatting domains** in email URLs. For example, hunt domains that look like your company domain or common sites but aren’t exact (like “micros0ft.com” or “contoso-security.com” instead of contoso.com). A heuristic: find URLs where the domain contains the string "contoso" but is not the exact contoso.com.  
    ```kql
    // Hunt for potential typosquat domains similar to 'contoso'
    EmailUrlInfo
    | where UrlDomain contains "contoso" and UrlDomain != "contoso.com"
    | summarize Examples=count() by UrlDomain
    | sort by Examples desc
    ```  
    This might reveal domains like "contoso-login.com" which could be used in phishing. The hunter can then check those domains’ reputation or search who received such links. This proactively identifies targeted phishing attempts that mimic the company’s brand.

- **Compliance Check:** While EmailUrlInfo is more for security, it can also assist compliance by tracking if users are being targeted by certain categories of content, or to ensure logging of clickable links (Safe Links) is working. Perhaps compliance wants to ensure that all emailed URLs are scanned (which having them in this table implies). Another angle: if there's a policy against certain types of links (like personal cloud storage links being sent), you could query that.  
  - *Basic Query:* **Usage of personal storage links:** If company policy says not to use personal Dropbox/Google Drive for work files, one could search for those domains in outgoing emails:  
    ```kql
    // Check for personal file-sharing links in outbound emails
    EmailUrlInfo
    | where UrlDomain in ("dropbox.com","drive.google.com","wetransfer.com")
      and NetworkMessageId in (EmailEvents | where EmailDirection == "Outbound" | select NetworkMessageId)
    | summarize count() by UrlDomain
    ```  
    If this shows a number of links, employees might be violating policy by sharing files via personal cloud links. Compliance can use that to educate or enforce alternative methods.  
  - *Advanced Query:* **Phishing defense coverage:** For compliance with security standards, an org might need to report on how many malicious URLs were detected and blocked. EmailUrlInfo plus UrlClickEvents can show if Safe Links is working. One approach: identify URLs that were later flagged (Safe Links click verdict) but initially present. Or simply count unique URL domains in email and see how many were categorized as malicious (if ThreatTypes in EmailEvents or if those URLs appear in UrlClickEvents with "Blocked"). If ThreatTypes doesn’t include "PhishURL", you may have to correlate with UrlClickEvents. For brevity:  
    ```kql
    // Check if known malicious domains (from a TI list) ever appeared in emails
    let badDomains = datatable(domain:string)["evil.com","malicious.org"];
    EmailUrlInfo
    | where UrlDomain in (badDomains)
    | distinct UrlDomain, NetworkMessageId
    ```  
    If any known bad domain is found in emails, compliance would ask if those were caught. You’d cross-check those NetworkMessageIds in EmailEvents to see if they were blocked or delivered. While this is more security, reporting these incidents is part of compliance with incident management processes. Generally, compliance might mandate that all email links are scanned – having this data available is evidence of that scanning.

### UrlClickEvents
**Schema Description:** The `UrlClickEvents` table records events of users **clicking Safe Links** in emails, Teams, or Office apps ([UrlClickEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table#:~:text=)). Safe Links is the feature that scans and wraps URLs for checking at time-of-click. Each entry includes the **Timestamp** of click, the full **Url** clicked, an **ActionType** indicating if the click was allowed or blocked by Safe Links (e.g., ClickAllowed, ClickBlocked) ([UrlClickEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table#:~:text=,being%20Email%2C%20Office%2C%20and%20Teams)), the **AccountUpn** of the user who clicked, the **Workload** (whether the click was from Email, Teams, or Office application) ([UrlClickEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table#:~:text=list%20,being%20Email%2C%20Office%2C%20and%20Teams)), the **NetworkMessageId** (if from an email, linking back to that email), and threat verdict info like **ThreatTypes** (malicious, phishing) and **DetectionMethods**. It also logs the user’s device public IP and whether they *clicked through* the warning (IsClickedThrough == true means they went past the Safe Links warning) ([UrlClickEvents table in the advanced hunting schema - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table#:~:text=the%20clicked%20link%2C%20generated%20by,0)). This table is crucial for understanding user behavior in response to phishing attempts and measuring effectiveness of Safe Links.

**Use Cases:**

- **Security Investigation:** If a user is compromised or fell for a phishing attack, UrlClickEvents can confirm if they clicked a malicious link. For instance, after a phishing email incident, investigators check this table to see who clicked the phishing URL and whether Safe Links blocked it or the user bypassed the warning.  
  - *Basic Query:* Find whether a specific user clicked on any malicious links recently. For example, if Bob received a phish, did he click it?  
    ```kql
    // Recent clicks by Bob that were classified as malicious
    UrlClickEvents
    | where AccountUpn == "bob@contoso.com" and ThreatTypes contains "Phish"
    | project Timestamp, Url, ActionType, IsClickedThrough, Workload
    ```  
    This shows Bob clicked a link that was flagged as phishing; if ActionType is "ClickBlocked" but IsClickedThrough is 1, it means Bob was warned but proceeded anyway (i.e., clicked through the block). That’s critical evidence in an investigation to determine user action.  
  - *Advanced Query:* For a particular phishing campaign, identify all users who clicked the link. If you have the NetworkMessageId of the phishing email or the URL itself, you can query by that. For example, using the URL domain:  
    ```kql
    // List of users who clicked any link on phishing domain "contoso-updates.com"
    UrlClickEvents
    | where Url contains "contoso-updates.com" and ThreatTypes has "Phish"
    | summarize ClickCount=count(), FirstClick=min(Timestamp) by AccountUpn, ActionType, IsClickedThrough
    ```  
    This reveals which users attempted to visit that phishing domain from their emails, and whether Safe Links blocked them or not. Investigators then know which users to follow up with (especially if they clicked through an allowed threat).

- **Threat Hunting:** UrlClickEvents is great for hunting because it directly shows user interaction with potentially malicious links. Hunters can search for patterns like users clicking through warnings, or high volumes of clicks on newly seen domains, etc. It’s essentially “who is interacting with shady stuff”.  
  - *Basic Query:* Hunt for any instance of **Safe Links bypass** – users clicking through a warning. Those events have IsClickedThrough = 1 and typically ActionType "ClickAllowed" (meaning they ignored the warning).  
    ```kql
    // All instances where users clicked through a Safe Links warning in last 30 days
    UrlClickEvents
    | where Timestamp > ago(30d) and IsClickedThrough == true
    | project Timestamp, AccountUpn, Url, ThreatTypes, Workload
    ```  
    A threat hunter would review these. If ThreatTypes indicated the URL was malicious and the user still proceeded, those users might need targeted security training or follow-up checks on their accounts/devices.  
  - *Advanced Query:* Look for **trending malicious URLs** – e.g., a particular URL or domain receiving many clicks across the organization. That could indicate a broad phishing campaign.  
    ```kql
    // Top 5 clicked malicious URL domains in the past week
    UrlClickEvents
    | where Timestamp > ago(7d) and ThreatTypes != ""  // only where a threat verdict exists (malicious)
    | summarize Clicks=count() by UrlDomain = tostring(parse_url(Url).Host)
    | sort by Clicks desc
    | take 5
    ```  
    This shows, for example, that `contoso-updates.com` had 10 clicks, `office-secure-login.net` had 8, etc. A hunter seeing these can drill down to who clicked (as above) and also feed these domains into threat intel or blocking. It’s essentially identifying the most successful phishing lures of the week.

- **Compliance Check:** UrlClickEvents can serve as a metric for security awareness (compliance with training) – e.g., are users clicking phishing links less over time? It can also help ensure that Safe Links is operational (if no data is coming in, that’s a problem). Additionally, for compliance, one might use it to ensure that no users are clicking on disallowed categories of sites (if ThreatTypes covers not just malware/phish but maybe blocked URL categories, though typically Safe Links focuses on malicious content).  
  - *Basic Query:* **User awareness metrics:** Count how many users clicked through warnings in a quarter. If compliance mandate is to reduce this number, you can track it.  
    ```kql
    // Number of distinct users who ignored Safe Links warnings (per month)
    UrlClickEvents
    | where IsClickedThrough == true
    | summarize UsersWhoClickedThrough=dcount(AccountUpn) by Month=bin(Timestamp, 30d)
    ```  
    If this number is going down after security training, compliance can show improvement. If not, additional training might be needed.  
  - *Advanced Query:* **Policy enforcement:** Perhaps there’s a policy that all external email links must be scanned and blocked if malicious. UrlClickEvents can be used to verify that malicious links indeed show as blocked. For instance, if any ThreatTypes has a value but ActionType was "ClickAllowed", that could mean the system thought it was malicious but still allowed (which shouldn’t happen normally unless policy was override-able). Checking for that scenario:  
    ```kql
    // Check if any known malicious link clicks were allowed through
    UrlClickEvents
    | where ThreatTypes contains "Malware" or ThreatTypes contains "Phish"
    | summarize AllowedCount=sumif(1, ActionType == "ClickAllowed"), Total=sum(1)
    ```  
    Ideally, AllowedCount should be 0 if ThreatTypes indicated bad content (since Safe Links should block). If not zero, that’s a compliance gap in security controls to investigate. Another compliance use: if certain departments shouldn’t be using external links, you could filter by AccountUpn (via IdentityInfo join to get Department) to see if, say, Finance team had any clicks on risky links and ensure they have extra controls. Compliance teams can then target additional controls or training at those groups.
