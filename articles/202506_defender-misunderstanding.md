---
title: "Microsoft Defender のよくある誤解"
emoji: "🛡" 
type: "tech" ## tech: 技術記事 / idea: アイデア記事
topics: [Microsoft Defender, Security] 
published: false
---

:::message
本ブログは2025年4月5日時点の情報を元に執筆しています。
:::

## 参考文献

## メモ
^[[XXX](https://XXX)]

```kql

```


**結論:**  
Microsoft Defender（以下Defender）は有料セキュリティソフトに劣るどころか、現行の最先端テストで満点評価を獲得しており、Defender for Endpoint（MDE）は従来のアンチウイルス（AV）機能を置き換えるものではなく補完するものです。自動ネットワーク切り離し（デバイス隔離）は状況に応じて「完全分離」か「選択的分離」を使い分けるべきで、自動化設定にも注意点があります。

## 1. Defenderは有料AVに劣っている？

第三者評価機関 AV-TEST の2025年4月の検証で、Defenderは「保護」「パフォーマンス」「使いやすさ」の各項目で満点（100/100/100）を獲得し、総合スコアでも常にトップクラスを維持しています[1]。  
また、AV-Comparativesの2023年テストでは、実際のマルウェア626サンプル中623件を検出・ブロックし、最高評価「ADVANCED+」を得ています[2]。

これらの結果は、Defenderが最新のAIおよびクラウド技術を活用し、有料製品と肩を並べる性能を備えていることを示しています。

## 2. 「MDEを入れたらアンチウイルスは不要」という誤解

- **Defender Antivirus（MDAV）** はWindows 8以降に標準搭載されたマルウェア検知・防御エンジンです。  
- **Microsoft Defender for Endpoint（MDE）** はエンドポイント検出・対応（EDR）機能を提供し、異常検知や詳細なフォレンジック、インシデント対応を実現するクラウドベースのソリューションです[3]。

MDEは侵入後の調査・対応を担う一方で、リアルタイムスキャンや定義ファイルベースの検出はMDAVが担います。そのため、MDEを導入してもAV機能（MDAV）は引き続き必要かつ動作し、両者を連携させることで多層防御を構築できます。

## 3. 「有料ソフトを入れるとDefenderは完全に停止する」という誤解

有料セキュリティソフトをインストールすると、Defenderのリアルタイムスキャンエンジンは一時的に休止しますが、以下のような**コア分離**や**ランサムウェア保護**などの重要機能はOSのカーネルレベルで動作し続けます[4]。  
これにより、有料ソフトとDefender機能が共存し、多層的な防御体制が可能です。

## 4. 「自動でネットワークを切り離すべき」という誤解

MDEのデバイス隔離には二つのモードがあります[5]。

1. **完全分離 (Full isolation)**  
   デバイスのすべての通信をブロックし、Defenderエージェントとの必要最小限の接続のみ許可。最も安全だが、業務に支障を来す可能性が高い。

2. **選択的分離 (Selective isolation)**  
   VPNや特定プロセス、IPアドレスなどの例外設定を許可しつつ、他の通信を遮断。管理ツールや重要サービスを継続利用できるため、検知対象デバイスの切り離しによる業務影響を抑制できる。

**ベストプラクティス:**  
- 自動で隔離アクションを実行する際は、まずは選択的分離を採用し、必須サービスを例外設定する。  
- 「全自動で完全分離」を安易に適用すると、調査・対応に必要な通信まで遮断し、かえって復旧作業を遅延させる恐れがあります[6][5]。  
- 定期的に隔離除外ルールを見直し、最小限の例外設定に留めることが重要です。

## 5. 除外設定に関する落とし穴

Defenderのスキャン除外設定は誤用すると保護レベルを大幅に低下させます。Microsoft公式ドキュメントでは、以下の一般的な誤りを避けるよう警告しています[7]。

- **システムドライブ（C:\ など）や重要フォルダ全体を除外しない**  
- **“.exe”や“.dll”など一般的な拡張子を除外しない**  
- **実行中プロセスのパスやフォルダを安易に除外しない**

不必要な除外は、正規のマルウェアやゼロデイ攻撃を見逃すリスクを高めるため、必ずビジネス要件とリスク評価に基づいて最小限に留めるべきです。

**まとめ:**  
Defenderは現在、第三者テストで有料製品と同等の保護性能を実証しています。MDEはAV機能を置き換えるものではなく、両者を連携させることでインシデント対応力を強化します。自動隔離は状況に応じて完全／選択的分離を使い分け、除外設定も最小限に抑えることで、Defenderの真価を引き出せます。

[1] https://www.av-test.org/en/antivirus/home-windows/manufacturer/microsoft/
[2] https://texal.jp/windows-defender-takes-a-big-hit-in-av-comparatives-protection-tests-microsoft-finally-takes-a-shot/
[3] https://a-zs.net/defender-difference/
[4] https://enjoykeiri.com/windows-defender-ultimate-security-settings/
[5] https://learn.microsoft.com/en-us/defender-endpoint/isolation-exclusions
[6] https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts
[7] https://learn.microsoft.com/ja-jp/defender-endpoint/common-exclusion-mistakes-microsoft-defender-antivirus
[8] https://jp-sec.github.io/blog/Endpoint-MDAV-2024-08-19/
[9] https://koneta.nifty.com/koneta_detail/1141008021121_1.htm
[10] https://lt-security.jp/howto/kujo/case01/step4.php
[11] https://jp.norton.com/blog/emerging-threats/windows-security
[12] https://support.kaspersky.com/kesmac/12.1_adminguide/ja-JP/276072.htm
[13] https://redresscompliance.com/how-microsoft-defender-antivirus-protects-your-pc/
[14] https://www.av-test.org/en/antivirus/home-windows/windows-10/february-2023/microsoft-defender-antivirus-consumer-4.18-231114/
[15] https://techdocs.broadcom.com/jp/ja/vmware-cis/vsphere/vsphere/6-7/vcenter-and-host-management-6-7/troubleshooting-overview-host-management/troubleshooting-hosts-host-management/troubleshooting-vsphere-ha-host-states-host-management/network-isolated-host-management.html
[16] https://www.av-test.org/en/antivirus/home-windows/windows-11/april-2024/microsoft-defender-antivirus-consumer-4.18-241213/
[17] https://learn.microsoft.com/ja-jp/defender-endpoint/isolation-exclusions
[18] https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-will-isolate-undiscovered-endpoints-to-block-attacks/
[19] https://jp-sec.github.io/blog/Endpoint-MDAV-2023-05-02/
[20] https://www.numberanalytics.com/blog/ultimate-guide-to-isolation-in-networking
[21] https://hybridbrothers.com/device-isolation-and-containment-strategies/
[22] https://jin-kuro.com/mde-customrule-isolation/
[23] https://gigazine.net/news/20180202-windows-defender-remove-cleaner-optimizer/
[24] https://www.hammock.jp/assetview/media/windows11_need-more-security.html
[25] https://portal.ct.gov/OCPD/Org-and-Admin/Public-Defender-Myths
[26] https://fresnocriminallawyer.com/10-common-misconceptions-about-criminal-defense-lawyers-and-the-truth-behind-them/
[27] https://jp-sec.github.io/blog/Endpoint-MDAV-2023-06-21/
[28] https://gigazine.net/news/20230515-windows-microsoft-defender-highest-system-load/
[29] https://www.av-comparatives.org/av-comparatives-awards-2023-for-microsoft/
[30] https://www.av-test.org/en/antivirus/home-windows/windows-10/february-2022/microsoft-defender-antivirus-consumer-4.18-221114/
[31] https://www.eset.com/jp/topics-home/need-for-security-software/
[32] https://learn.microsoft.com/ja-jp/azure/defender-for-cloud/faq-general
[33] https://learn.microsoft.com/ja-jp/defender-for-identity/technical-faq
[34] https://www.ntt.com/business/services/network/internet-connect/ocn-business/bocn/knowledge/archive_62.html
[35] https://express-knowledge.si-system.jp/hc/ja/articles/33587949089305-%E3%82%A8%E3%82%AF%E3%82%B9%E3%83%97%E3%83%AC%E3%82%B9%E3%82%92%E8%B5%B7%E5%8B%95%E3%81%97%E3%82%88%E3%81%86%E3%81%A8%E3%81%99%E3%82%8B%E3%81%A8-Microsoft-Defender%E3%81%AE%E3%82%A6%E3%82%A4%E3%83%AB%E3%82%B9%E8%84%85%E5%A8%81%E3%81%AE%E3%83%A1%E3%83%83%E3%82%BB%E3%83%BC%E3%82%B8%E3%81%8C%E8%A1%A8%E7%A4%BA%E3%81%95%E3%82%8C%E8%B5%B7%E5%8B%95%E3%81%A7%E3%81%8D%E3%81%BE%E3%81%9B%E3%82%93-%E3%81%A9%E3%81%86%E3%81%97%E3%81%9F%E3%82%89%E8%89%AF%E3%81%84%E3%81%A7%E3%81%99%E3%81%8B
[36] https://learn.microsoft.com/ja-jp/defender-xdr/top-scoring-industry-tests
[37] https://www.av-test.org/en/antivirus/business-windows-client/manufacturer/microsoft/
[38] https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine
[39] https://support.huntress.io/hc/en-us/articles/36531241186707-Microsoft-Defender-for-Business-Endpoint-Best-Practices
[40] https://learn.microsoft.com/ja-jp/defender-endpoint/mdav-scan-best-practices
[41] https://learn.microsoft.com/ja-jp/defender-endpoint/defender-endpoint-false-positives-negatives
[42] https://www.eset.com/jp/topics-home/security-measures-for-windows-10-11/
