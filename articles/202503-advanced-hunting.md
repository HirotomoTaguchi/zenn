---
title: "Advanced Hunting のユースケースをメモってく（WIP）"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [Microsoft Defender XDR, Microsoft Defender for Endpoint, Microsoft Defender for Office365] 
published: true
published_at: 2025-03-15
---
Advanced Hunting のユースケースをメモってく（WIP）

# アラートと動作

## AlertEvidence
### 概要
`AlertEvidence` テーブルには、Defender のアラートをトリガーしたイベントに関する追加情報が保存されています。アラートをキーに様々な情報を確認できるので、インシデントレスポンスや定期的な振り返りなどのユースケースで活用できます。

### 特定のアラートのエビデンスエンティティを取得

特定のアラート（AlertIdまたはTitle別）のエビデンスエンティティを取得します。これにより、さらなる分析のために、その警告に関与するすべてのファイル、IPを表示します。ここでは、アラートのタイトルをベースに検索を行います。

```kql
// 特定のアラートのエビデンスエンティティを取得
AlertEvidence
| where Title == "Suspicious PowerShell Behavior"
| project Timestamp, EntityType, EvidenceRole, FileName, SHA1, AccountName, DeviceName
```

## AlertInfo

## BehaviorEntities

## BehaviorInfo

# アプリと ID

## AADSignInEventsBeta

## AADSpnSignInEventsBeta

## CloudAppEvents

## IdentityInfo

## IdentityLogonEvents

## OAuthAppInfo
- リスクの高いOAuthアプリを発見する。^[[Microsoft 365 環境におけるOAuthアプリのリスクと対策](https://zenn.dev/hirotomotaguchi/articles/202504_m365-oauth-security#oauth-%E3%82%A2%E3%83%97%E3%83%AA%E3%81%AE%E8%A6%8B%E3%81%88%E3%82%8B%E5%8C%96%E3%81%A8%E5%80%8B%E5%88%A5%E3%81%AE%E5%88%B6%E5%BE%A1)]
```kql
OAuthAppInfo
| where AppStatus == "Enabled"
| where PrivilegeLevel == "High"
| where VerifiedPublisher == "{}" and AppOrigin == “External”
```

# メールとコラボレーション

## EmailAttachmentInfo

## EmailEvents
### 概要
`EmailEvents` テーブルにはExcange Onlineのメールのログが保存されています。ここでは、Defender for Office 365の結果などメールに関わる情報も踏まえた分析を行うことができます。

### MDOのAIで脅威のあるメールと判定されたメールの一覧を取得する

MDOのAIで脅威のあるメールと判定されたメールの一覧を取得するクエリは以下の通りです。
```kql
EmailEvents
| where isnotempty(ThreatClassification)
| summarize Count = dcount(NetworkMessageId) by ThreatClassification
| render columnchart
```

## EmailPostDeliveryEvents

## EmailUrlInfo

## UrlClickEvents

# デバイス

## DeviceEvents

## DeviceFileCertificateInfo

## DeviceFileEvents

## DeviceImageLoadEvents

## DeviceInfo

## DeviceLogonEvents

## DeviceNetworkEvents

## DeviceNetworkInfo

## DeviceProcessEvents

## DeviceRegistryEvents

# Defender 脆弱性の管理

## DeviceTvmInfoGathering

## DeviceTvmInfoGatheringKB

## DeviceTvmSecureConfigurationAssessment

## DeviceTvmSecureConfigurationAssessmentKB

## DeviceTvmSoftwareEvidenceBeta

## DeviceTvmSoftwareInventory

## DeviceTvmSoftwareVulnerabilities

## DeviceTvmSoftwareVulnerabilitiesKB

# 露出管理

## ExposureGraphEdges

## ExposureGraphNodes
