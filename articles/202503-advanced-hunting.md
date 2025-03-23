---
title: "Advanced Hunting のユースケースをメモってく（WIP）"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [Intune, MAC] 
published: false
published_at: 2024-12-31 08:00
---
Advanced Hunting のユースケースをメモってく（WIP）

# アラートと動作

## AlertEvidence
### 概要
`AlertEvidence` スキーマは、アラートをトリガーしたイベントに関する追加情報を提供します。]

### 特定のタイトルを持つアラートのすべてのエビデンスエンティティを取得

特定のアラート（AlertIdまたはTitle別）のエビデンスエンティティを取得します。これにより、さらなる分析のために、その警告に関与するすべてのファイル、IPを表示します。

```kql
// 特定のタイトルを持つアラートのすべてのエビデンスエンティティを取得
AlertEvidence
| where Title == "Suspicious PowerShell Behavior"
| project Timestamp, EntityType, EvidenceRole, FileName, SHA1, AccountName, DeviceName
```

### 概要


## AlertInfo

## BehaviorEntities

## BehaviorInfo

# アプリと ID

## AADSignInEventsBeta

## AADSpnSignInEventsBeta

## CloudAppEvents

## IdentityInfo

## IdentityLogonEvents

# メールとコラボレーション

## EmailAttachmentInfo

## EmailEvents

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
