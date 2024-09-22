---
title: "[macOS]Intune を利用して、CrowdStrikeエージェント(Falcon Sensor)を配信してみた"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [CrowdStrike, Intune] 
published: false
---

本日は、Microsoft Intuneを使用してCrowdStrike Falcon SensorをmacOSに配布する方法についてご紹介します。今回の手順では、システム拡張やフルディスクアクセス（FDA）の承認をMDMプロファイルを通じて事前に設定し、手動での承認手順を省略する方法を解説します。

## 免責事項
- ネットワーク要件やCrowdStrikeの利用条件は、[サポートサイト](https://falcon.us-2.crowdstrike.com/documentation/22/falcon-sensor-for-mac#:~:text=%3C/dict%3E-,System%20requirements,-Installing%20the%20Falcon) を参照してください。
- 本手順は公式ドキュメントに基づき、Microsoft Intuneでの実装を説明しています。今後のmacOSのアップデートにより手順が変更される可能性がありますので、CrowdStrikeの公式資料を常に確認してください。

## 事前準備タスク

### Falcon Sensor パッケージのダウンロード

Falcon Sensor のパッケージは、CrowdStrikeの管理コンソール（Falcon Console）からダウンロードできます。以下の手順で最新のmacOS用センサーパッケージを取得してください。

1. **Falcon Console** にログインします。
2. [**Hosts > Sensor Downloads**](https://falcon.us-2.crowdstrike.com/hosts/sensor-downloads) ページに移動します。
3. 最新のmacOS用のパッケージをダウンロードします。

### Customer IDの取得

Falcon Sensor のインストールには、**Customer ID (CID)** が必要です。CID は次の手順で確認できます。

1. **Falcon Console** にログインします。
2. [**Support > Sensor Downloads**](https://falcon.us-2.crowdstrike.com/hosts/sensor-downloads) ページに移動し、CID を確認します。

### MDMプロファイルの準備

**Intune** でシステム拡張やフルディスクアクセスの設定を事前に承認するため、MDMプロファイルを作成・配布する必要があります。これにより、手動での承認を回避し、スムーズな配布を実現します。

1. **Intune管理ポータル** にアクセスします。
2. **デバイス > 構成プロファイル** に移動し、「+プロファイルの作成」をクリックします。
3. **macOS** を選択し、**カスタム設定** を使用して次のプロファイルを設定します。

   - **システム拡張の承認**：
     - チーム識別子：`X9E956P446`
     - システム拡張：`com.crowdstrike.falcon.Agent`
   
   - **フルディスクアクセス (FDA)**：
     - アプリケーション識別子：`com.crowdstrike.falcon.Agent`

これらのプロファイルは、**macOS Big Sur 11.0以降**に必須です。MDMプロファイルを正しく同期しない場合、手動でのシステム拡張承認が必要になるため注意が必要です。

## 配信手順

### 1. Intuneへのパッケージアップロード

1. **Intune管理ポータル** にログインします。
2. **アプリ > アプリの追加** に移動し、「macOS LOBアプリ」を選択します。
3. 「ファイルの選択」から、ダウンロードしたFalcon Sensorのパッケージ（.pkgファイル）をアップロードします。
4. アプリ名や説明を入力し、**保存** します。

### 2. MDMプロファイルの適用

1. **デバイス > 構成プロファイル** に戻り、作成したシステム拡張とFDA承認のプロファイルを選択します。
2. 「割り当て」タブで、Falcon Sensorを配布したいデバイスグループを選択します。
3. プロファイルが正常に適用されたか確認します。

### 3. 配信ポリシーの作成

次に、**配信ポリシー** を作成します。

1. **デバイス > 構成プロファイル** に移動し、新しいプロファイルを作成します。
2. **コマンド実行** タスクを追加し、以下のコマンドを実行するよう設定します。

    ```bash
    sudo /Applications/Falcon.app/Contents/Resources/falconctl license <取得したCID>
    ```

3. **割り当て** タブで、配信対象のデバイスグループを選択します。

### 4. センサーの動作確認

Falcon Sensorが正しくインストールされたかどうかを確認するには、以下のコマンドをmacOSのターミナルで実行します。

```bash
sudo /Applications/Falcon.app/Contents/Resources/falconctl stats
```

表示される内容には、以下の情報が含まれます。

- エージェントID（AID）
- バージョン
- CID など

正しくインストールされている場合は、CrowdStrike管理コンソールにも反映されます。ただし、反映には数分〜10分程度のタイムラグが生じる可能性があります。

## 終わりに

今回は、**Intune** を使用して **CrowdStrike Falcon Sensor** をmacOSに配布する方法を解説しました。公式の手順に従って適切なMDMプロファイルを使用することで、手動での承認を省略し、効率的にセンサーをデプロイできます。今後もCrowdStrikeの新機能や手順について検証していく予定ですので、ブログでの続報をお楽しみに。

## 参考資料
- [Falcon Sensor for Mac ドキュメント](https://falcon.us-2.crowdstrike.com/documentation/22/falcon-sensor-for-mac)
