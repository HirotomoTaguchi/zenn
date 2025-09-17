---
title: "【注意喚起】Sentinelのデータレイクを使っていると思ったら50万課金されてしまった話"
emoji: "🛡" 
type: "tech" ## tech: 技術記事 / idea: アイデア記事
topics: [Microsoft Defender, Security, Microsoft Sentinel] 
published: false
---

この記事は、Microsoft Sentinelのデータレイク機能を検証していたところ、予想外の50万円の課金が発生してしまった体験談です。まず最初にお伝えしたいのは、これはMicrosoft社やそのサポートに問題があったのではなく、私の理解不足と勘違いに起因するものだということです。 Microsoft社のサポートチームは非常に丁寧で迅速な対応をしてくださいました。

正直なところ、自分の浅はかさを世間に晒すことになりますし、せっかく登場したデータレイク機能についてのミスリードにも繋がるので後悔を悩みました。SNSにはマイクロソフト社に親を殺されたかのように非難する人がいて、そういった方達に変な切り取られ方をしないかとドキドキしています。しかし、この記事を書く目的は、同じような誤解から高額な課金を受けてしまう方が出ないよう、私の失敗体験を共有することです。特にMicrosoft Sentinelのデータレイク機能を検証される方には、ぜひ最後まで読んでいただければと思います。

## 何が起きたのか

先日、Zennで記事を書いたとり、Microsoft Sentinelのデータレイクの機能を検証していました。

https://zenn.dev/hirotomotaguchi/articles/202508_microsoft-sentinel-data-lake

2025年8月下旬、Azure の課金画面を確認したところ、Sentinelリソースで約50万円という異常な金額の課金が発生していることを発見しました。

私の認識では：
- 90日間で90MB程度のデータしか取り込んでいない
- 特に大きな作業は実施していない
- データレイクのプレビュー期間中で、30日間の無料ストレージが含まれているはず

この状況では到底50万円もの課金が発生するとは思えず、すぐにMicrosoftサポートに問い合わせを行いました。

## 課金の真の原因

### 私が行った操作

私は「最近パブリックプレビューで登場したデータレイクにデータを取り込みそれをリストアする検証」を実施していました。具体的には以下画面から**復元操作**を行っていました。

```
Defender ポータル > [Microsoft Sentinel] > [Data lake exploration] > [Search & restore]
```

### 私の勘違いポイント

ここに大きな勘違いがありました。私は以下のように思い込んでいました：

1. **Data Lake の復元機能だと思っていた**
   - 実際は：Data Lake では復元はサポートされていない
   - 実際は：Azure Monitor サービスの「検索ジョブ」機能だった

2. **プレビュー期間中だから無料だと思っていた**
   - 実際は：検索ジョブと復元操作には別途料金が発生する

3. **少量のデータだから安いはずだと思っていた**
   - 実際は：検索ジョブと復元操作は独自の料金体系を持つ

## 技術的な詳細

### Data Lake と Azure Monitor の違い

Microsoft サポートからの説明によると：

**Microsoft Sentinel Data Lake では：**
- 復元機能は**サポートされていない**
- Data Lake 配下に表示される検索ジョブの項目は、実際には Azure Monitor サービスの機能

**Azure Monitor の検索ジョブでは：**
- 独自の料金体系で課金される
- 1回実行すると最低２TB、12時間分課金される
- 復元されたデータは削除するまで継続的に課金される
- 復元されたテーブルには `_RST` サフィックスが付く（例：`AADNonInteractiveUserSignInLogs_656_RST`）

つまり、Azure Monitorの復元 $0.10(≒15円/1日/GB) × 2TB × 利用日数 の課金が

## 学んだ教訓と対策

### ①. UIの表示に惑わされない

Data Lake のインターフェース内に表示されているからといって、それがすべて Data Lake の機能ではありませんでした。
今回のケースでは、Azure Monitor の機能が混在しており、

### ②. 復元操作は慎重に

復元されたデータは、**削除するまで継続的に課金される**。検証目的であっても、使用後は必ず削除することが重要。

### ③. 料金体系を正しく理解する

プレビュー期間中であっても、すべての機能が無料とは限らない。特に：
- Data Lake レベル自体は30日間無料
- しかし検索ジョブや復元操作は別料金体系

新しい機能を試す前に、必ず以下を確認する：
- [Azure Monitor で検索ジョブを実行する - 価格モデル](https://learn.microsoft.com/ja-jp/azure/azure-monitor/logs/search-jobs?tabs=portal-1%2Cportal-2#pricing-model)
- [Azure Monitor でログを復元する - 価格モデル](https://learn.microsoft.com/ja-jp/azure/azure-monitor/logs/restore?tabs=api-1#pricing-model)

1. **課金アラートの設定**
   - 想定外の課金をすぐに検知できるよう、低めの閾値でアラートを設定

2. **復元操作後の確認**
   - `_RST` サフィックスの付いたテーブルが作成されていないか確認
   - 不要な復元テーブルは即座に削除

3. **ドキュメントの熟読**
   - 新機能を試す前に、必ず料金体系に関する公式ドキュメントを確認
   - Sentinelのように、Azure MonitorやLog Analyticsなど複数製品にまたがる場合はそれも要確認

## さいごに

この体験を通じて、クラウドサービスの新機能を試す際の慎重さの重要性を痛感しました。Microsoft Sentinel のデータレイク機能自体は非常に有用な機能ですが、その周辺機能の料金体系については正しい理解が必要です。

改めて強調したいのは、これは私の理解不足が原因であり、Microsoft社に問題があったわけではありません。

この記事が、同じような失敗を防ぐ一助となれば幸いです。

*参考リンク：*
- [Microsoft Sentinel でデータ層とリテンション期間を管理する](https://learn.microsoft.com/ja-jp/azure/sentinel/manage-data-overview)
- [Microsoft Sentinel で大規模なデータセット間で特定のイベントを検索する](https://learn.microsoft.com/ja-jp/azure/sentinel/search-jobs?tabs=defender-portal)
- [コストを計画し、Microsoft Sentinel の価格と課金を理解する](https://learn.microsoft.com/ja-jp/azure/sentinel/billing)
- [Azure Monitor でログを復元する](https://learn.microsoft.com/ja-jp/azure/azure-monitor/logs/restore)
