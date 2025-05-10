---
title: "Microsoft Defender Advanced Hunting でリモートマネジメントモニタリング（RMM）ツールの不正利用による脅威を検知する"
emoji: "💻" 
type: "tech" ## tech: 技術記事 / idea: アイデア記事
topics: [Microsoft Defender, Security] 
published: false
---

今回は、Microsoft Defender for Endpoint のAdvanced Hunting機能を活用し、リモートマネジメント・モニタリングツール（RMMツール）の通信を検出する方法について紹介します。

## 前提条件
- Microsoft Defender for Endpoint P2 ライセンス（Defender for Businessでは対象外）
- Microsoft Defender for Endpoint P2 が対象デバイスにオンボートされていること

## なぜRMMツールを監視する必要があるのか？

AnyDesk や TeamViewer などがに代表されるRMMツールは、IT管理者がリモートからシステムをメンテナンスしたり、サポートを提供したりするための非常に便利なツールです。しかし、その強力な機能が悪用されると、セキュリティ上の大きな脅威となり得ます。

最近のランサムウェア攻撃や標的型攻撃の中では、攻撃者がRMMツールを不正にデバイスに導入させ、遠隔操作でデバイス・内部ネットワークに侵入するケースが後を絶ちません。下記図が示す通り、2024年以降RMMツールの利用した攻撃キャンペーンが爆増しています。

![image](https://github.com/user-attachments/assets/e3fa0d29-eb9e-436c-b375-1f6766293f6b)
*出所: [Remote Monitoring and Management (RMM) Tooling Increasingly an Attacker’s First Choice | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/remote-monitoring-and-management-rmm-tooling-increasingly-attackers-first-choice)*

攻撃者は正規のRMMツールを不正に利用して環境に侵入し、機密情報を窃取したり、マルウェアを拡散したりします。マイクロソフト社が公表している「Microsoft Digital Defense Report 2024^[[URL](https://www.microsoft.com/en-us/security/security-insider/intelligence-reports/microsoft-digital-defense-report-2024?msockid=0d4bd66716e762e62137c358170d6324)]」においても、ヘルプデスクを装った攻撃者がRMMツールをインストールさせるような手口が攻撃のトレンドになっていることが言及されていました。また、従業員が組織の許可なくRMMツールを使用する「シャドーIT」も、セキュリティリスクを高める要因となります。

加えて、RMMツール自体は悪意のあるツールではなく、通常の業務でも利用することが多いことから、FWやSWG、EDRで検出されない可能性があるという点も非常に厄介です。例えば、EDR導入していて、攻撃者のサーバーに直接通信しようとすると、EDR側で検出することがありますが、RMMツールでは対象外となってしまうことがあります。（もちろん、製品や設定によります。）そのため、自社環境で許可されていないRMMツールの通信を迅速に検出し、潜在的な脅威を排除することが重要です。

## クエリの解説

今回紹介するクエリは、既知のRMMツールのURLをまとめたリストを活用し、Microsoft Defender for Endpoint P2 がオンボートされている対象デバイスがこれらのURLに通信を試みた際に検出するものです。

```kql
let RMMList = externaldata(URI: string, RMMTool: string)
    [h'https://raw.githubusercontent.com/jischell-msft/RemoteManagementMonitoringTools/refs/heads/main/Network%20Indicators/RMM_SummaryNetworkURI.csv']
    with (format="csv", ignoreFirstRecord=true);
let RMMUrlDynamicList =
    RMMList
    | summarize make_list(URI);
DeviceNetworkEvents
| where RemoteUrl has_any (RMMUrlDynamicList) // dynamic 配列を使用
```

検出画面はこちらです。画面見ていただくと分かる通り、anydesk.exe は anydesk 社に署名されているので、デフォルトの検出だけでは正当な利用か悪意がある利用なのかが判別しにくいです。（もちろん、ツールの使用やポリシーによっては検出する可能性もあります。）

![image](https://github.com/user-attachments/assets/2d2a2930-d63d-4aae-a5e4-04e4ce5ba026)


### Microsoft Defender Advanced Hunting でリモートマネジメントモニタリング（RMM）ツールの不正利用による脅威を検知する

1.  **`externaldata`演算子**:
    まず、`externaldata`演算子を使用して、GitHub上で公開されているRMMツールのネットワークインジケータ（URIとツール名）のリスト（CSVファイル）を外部データとして読み込みます。このリストには、Action1, Addigy, AeroAdmin, AnyDesk, Atera, TeamViewerなど、多数のRMMツールに関連するURIが含まれています。
2.  **RMMツールのURIリスト作成**:
    次に、読み込んだ`RMMList`からURIのみを抽出し、`make_list()`関数を使って動的な配列 `RMMUrlDynamicList` を作成します。
3.  **RMMツール関連の通信検知**:
    最後に、`RemoteUrl` フィールド（接続先のURL）が、先ほど作成した `RMMUrlDynamicList` のいずれかのURLを含んでいるイベントを `has_any` 演算子で検索します。これにより、監視対象のRMMツールへのネットワーク接続が検知されます。

## このクエリで検出できる可能性があるリスク

このクエリを実行することで、MDEがオンボートされている端末に対しての以下のようなリスクを検出できます。

* **不正アクセスと遠隔操作**:
    攻撃者が盗んだ認証情報や脆弱性を利用して正規のRMMツールを組織の管理外で起動し、内部システムへ不正にアクセス・遠隔操作しようとする試みを検知できます。これにより、ランサムウェア攻撃の初期段階や持続的な不正アクセス（APT攻撃など）の兆候を捉えることが期待できます。
* **シャドーITの検出**:
    従業員がIT部門の許可なく、利便性のために個人的にRMMツールをインストール・使用しているケースを発見できます。これらの未管理のツールは、セキュリティポリシーの不履行や脆弱性の放置に繋がり、攻撃の足がかりとなる可能性があります。
* **ラテラルムーブメント（内部活動）の検知**:
    既にネットワーク内に侵入した攻撃者が、他の端末へRMMツール（例：ScreenConnect, VNC）を利用して活動範囲を水平展開（ラテラルムーブメント）しようとする動きを検知する手がかりとなります。特に、通常RMMツールを使用しないサーバーセグメントや特定のユーザー群からのRMM通信は要注意です。
* **データ窃取の初期兆候**:
    攻撃者が機密情報を外部に持ち出す準備段階として、RMMツールのファイル転送機能などを利用してデータを集約したり、外部のストレージサービスへ接続しようとしたりする際の通信を検知できる可能性があります。
* **マルウェアによるRMMツールの不正利用**:
    一部のマルウェアは、攻撃者によるリモートコントロールを可能にするために、バックドアとしてRMMツールを密かにインストールし、悪用します。このクエリは、そのようなマルウェアによって確立されたRMM通信を検知するのに役立ちます。

## 活用上の注意点

* **正規利用との区別（誤検知の低減）**:
    組織内で正式に利用が許可されているRMMツールや、特定の部署・ユーザーによる正当な利用も検知される可能性があります。そのため、検知されたアラートが真の脅威なのか、正規の利用なのかを切り分ける運用（ホワイトリストの作成、部署への確認など）が重要になります。例えば、特定のIPアドレスや部署からの通信を除外するフィルタを追加するなどのカスタマイズが考えられます。
* **外部リストの管理**:
    クエリが参照する外部リストの内容は、作成者によって管理されています。リストの正確性や網羅性、更新頻度を把握し、必要であれば自組織でリストを管理・カスタマイズすることも検討してください。
* **継続的監視**:
    Microsoft Defender for Endpoint ではカスタム検出といって、クエリを登録しておくと自動で検知をしてくれる機能があります。そちらを利用することで、継続的に監視ができます。
* **本件以外の対策**:
    当然の話ですが、本件以外の対策は平行して実施することを推奨します。たとえば、攻撃者にRMMツールをインストールさせない入口対策（メールセキュリティ等）、端末の管理者権限の適正化、FWやSWGなどでの通信先の絞り込みなどが考えられます。

## まとめ

今回紹介したMicrosoft Defender Advanced Hunting クエリは、RMMツールを悪用したサイバー攻撃や、組織内のポリシー違反となるシャドーITの発見に非常に有効です。このクエリを定期的に実行し、検知されたイベントを適切に調査することで、セキュリティインシデントの早期発見と対応、そして組織全体のセキュリティ体制の強化に繋げることができます。

是非、このクエリを自社の環境で試し、セキュリティ監視の一助としてご活用ください。

## 参考元・謝辞

本記事内でご紹介したクエリは、GitHub にて Steven Lim 氏が公開されたクエリ^[[URL](https://github.com/SlimKQL/Hunting-Queries-Detection-Rules/blob/main/Sentinel/Detecting%20Unauthorized%20RMM%20Instances%20in%20Your%20MDE%20Environment.kql)]を、私の要件に基づいて若干のカスタマイズをしたものとなります。Steven Lim 氏にはこの場を借りて感謝申し上げます。また、RMMのリストを作ってGithubで公開してくださった J Schell 氏にも感謝申し上げます。本当に助かりました！
