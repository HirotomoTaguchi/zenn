---
title: "[macOS]Intune を利用して、CrowdStrikeエージェント(Falcon Sensor)を配信してみた"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [CrowdStrike, Intune] 
published: false
---

## はじめに

CrowdStrike Falcon sensorは、次世代のアンチウイルス（NGAV）、エンドポイントの検出と応答（EDR）、マネージドな脅威ハンティング、脅威インテリジェンスオートメーションを単一の軽量センサーで統合することで、侵害を阻止します。本ドキュメントでは、Microsoft Intuneを使用してCrowdStrike Falcon sensorをデバイスに展開する手順を解説します。

## 免責事項

- 本手順はmacOS Big Sur 11以降を対象としています。
- ネットワーク要件等のCrowdStrikeの利用条件は、[サポートサイト](https://falcon.us-2.crowdstrike.com/documentation/22/falcon-sensor-for-mac#:~:text=%3C/dict%3E-,System%20requirements,-Installing%20the%20Falcon)を参照してください。
- 今後発生するmacOSのアップデート等により、手順が変更になる可能性があります。常に最新の状態を維持することは難しいため、実際に展開する際はCrowdStrike社が提供する最新の手順を併せてご確認ください。

## 事前準備

### 1. Falcon Sensorパッケージのダウンロード

[Falcon Console](https://falcon.us-2.crowdstrike.com/hosts/sensor-downloads) からmacOS用の最新のFalcon Sensorパッケージをダウンロードします。

### 2. Customer IDの取得

Falcon Sensorのインストールにはチェックサム付きのCustomer ID（CID）が必要です。CIDは[Falcon Console](https://falcon.us-2.crowdstrike.com/support/sensor-downloads)の上部に「<32文字の英数字>-<2文字の英数字>」の形式で記載されています。

### 3. Intuneへのパッケージのアップロード

ダウンロードしたFalcon SensorパッケージをIntuneのアプリケーションに追加します。

1. [Microsoft Endpoint Manager管理センター](https://endpoint.microsoft.com/)にサインインします。
2. 「アプリ」>「macOS」>「アプリの追加」の順に選択します。 
3. 「アプリの種類」で「macOS（pkg）」を選択し、「アプリパッケージファイル」でダウンロードしたpkgファイルを指定します。
4. 「OK」をクリックし、アプリの情報を入力して「追加」をクリックします。

### 4. 構成プロファイルの作成

Falcon Sensorを正常に動作させるため、以下の構成プロファイルをIntuneで作成します。

#### 4-1. システム拡張の承認

1. 「デバイス」>「構成プロファイル」>「プロファイルの作成」の順に選択します。
2. 「プラットフォーム」で「macOS」、「プロファイルの種類」で「テンプレート」を選択します。
3. 「テンプレート名」で「システム拡張」を選択し、「作成」をクリックします。
4. 任意のプロファイル名（例：CrowdStrike - システム拡張の承認）を入力します。
5. 「構成設定」で以下を設定し、「OK」をクリックします。
   - ユーザーがシステム拡張機能を承認できるようにする：オン
   - 許可されたシステム拡張機能：
     - CrowdStrike Inc.：X9E956P446
       - 許可されたシステム拡張機能：com.crowdstrike.falcon.Agent
       - 許可されたシステム拡張機能の種類：
         - エンドポイントセキュリティ拡張機能
         - ネットワーク拡張機能
6. 「割り当て」タブで「含めるグループの選択」をクリックし、このプロファイルを割り当てるユーザーまたはデバイスグループを選択します。「次へ」をクリックします。  
7. 「確認と作成」をクリックし、構成内容を確認して「作成」をクリックします。

#### 4-2. ネットワークコンテンツフィルタの構成

1. 「デバイス」>「構成プロファイル」>「プロファイルの作成」の順に選択します。 
2. 「プラットフォーム」で「macOS」、「プロファイルの種類」で「テンプレート」を選択します。
3. 「テンプレート名」で「ネットワークコンテンツフィルタ」を選択し、「作成」をクリックします。
4. 任意のプロファイル名（例：CrowdStrike - ネットワークフィルタ）を入力します。
5. 「構成設定」で以下を設定し、「OK」をクリックします。
   - フィルタ名：任意の名前  
   - 識別子：com.crowdstrike.falcon.App
   - 組織：CrowdStrike Inc.
   - フィルターソケット：はい
   - ソケットフィルターのバンドルID：com.crowdstrike.falcon.Agent
   - ソケットフィルターの指定要件：identifier "com.crowdstrike.falcon.Agent" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "X9E956P446"
6. 「割り当て」タブでプロファイルを割り当てるグループを選択し、「次へ」をクリックします。
7. 「確認と作成」をクリックし、構成内容を確認して「作成」をクリックします。

#### 4-3. Full Disk Access（完全ディスクアクセス）の承認

1. 「デバイス」>「構成プロファイル」>「プロファイルの作成」の順に選択します。
2. 「プラットフォーム」で「macOS」、「プロファイルの種類」で「テンプレート」を選択します。
3. 「テンプレート名」で「プライバシー設定」を選択し、「作成」をクリックします。
4. 任意のプロファイル名（例：CrowdStrike - Full Disk Access）を入力します。
5. 「構成設定」で以下のXMLを入力し、「OK」をクリックします。

```xml
<dict>
  <key>SystemPolicyAllFiles</key>
  <array>
    <dict>
      <key>Allowed</key>
      <true/>
      <key>CodeRequirement</key>
      <string>identifier "com.crowdstrike.falcon.Agent" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = X9E956P446</string>
      <key>Comment</key>
      <string></string>
      <key>Identifier</key>
      <string>com.crowdstrike.falcon.Agent</string>
      <key>IdentifierType</key>
      <string>bundleID</string>
      <key>StaticCode</key>
      <false/>
    </dict>
    <dict>
      <key>Allowed</key>
      <true/>
      <key>CodeRequirement</key>
      <string>identifier "com.crowdstrike.falcon.App" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = X9E956P446</string>
      <key>Comment</key>
      <string></string>
      <key>Identifier</key>
      <string>com.crowdstrike.falcon.App</string>
      <key>IdentifierType</key>
      <string>bundleID</string>
      <key>StaticCode</key>
      <false/>
    </dict>
  </array>
</dict>
```

6. 「割り当て」タブでプロファイルを割り当てるグループを選択し、「次へ」をクリックします。  
7. 「確認と作成」をクリックし、構成内容を確認して「作成」をクリックします。

## Falcon Sensorの展開

### 1. IntuneでのCrowdStrike Falcon展開

1. [Microsoft Endpoint Manager管理センター](https://endpoint.microsoft.com/)にサインインします。
2. 「アプリ」>「macOS」を選択します。
3. 「CrowdStrike Falcon Sensor」を選択し、「割り当て」をクリックします。
4. 「割り当ての追加」をクリックし、Falcon Sensorを展開するユーザーまたはデバイスグループを選択します。
5. 「OK」をクリックし、割り当てを保存します。

### 2. ライセンス認証

Intuneから展開後、各デバイスで以下のコマンドを実行しライセンス認証を行います。`<CID>`は事前準備で取得したCustomer IDに置き換えてください。

```bash
sudo /Applications/Falcon.app/Contents/Resources/falconctl license <CID>
```

## 動作確認

### ターミナルでのコマンド実行

ターミナルで以下のコマンドを実行し、Falcon Sensorが正常に動作していることを確認します。

```bash
sudo /Applications/Falcon.app/Contents/Resources/falconctl stats
```

出力にはエージェントID（AID）、バージョン、CIDなどの情報が含まれます。出力が異なる場合は、[トラブルシューティング](https://falcon.us-2.crowdstrike.com/documentation/22/falcon-sensor-for-mac#troubleshootinganinstallation)を参照してください。

### Falcon管理コンソールでの確認

Falcon管理コンソールのホスト一覧画面から、インストールが成功したか確認できます。情報が反映されるまでには数分から10分程度のタイムラグがあります。

## まとめ

本ドキュメントではIntuneを使用してCrowdStrike Falcon Sensorをデバイスに展開する手順を説明しました。事前にMDMで必要な構成プロファイルを配布することで、展開をスムーズに行うことができます。セキュリティ対策の要であるエンドポイント検知・応答（EDR）を適切に導入することで、サイバー攻撃のリスクを大幅に軽減できます。ぜひ参考にしていただき、セキュアなIT環境の構築にお役立てください。

## 参考資料
- [Falcon Sensor for Mac - Official Documentation](https://falcon.us-2.crowdstrike.com/documentation/22/falcon-sensor-for-mac)
