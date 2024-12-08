---
title: "【小ネタ】Sentinelのセキュリティ運用状況を月次で集計しSlackで通知する"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [Sentinel] 
published: true
published_at: 2024-12-09 07:00
---

Microsoft Security Advent Calendar 2024 の9日目の記事です。本記事では、Logic AppとKQLクエリを組み合わせて、前月のインシデント集計結果をSlackに自動通知するまでの流れと、その実装上のポイントを紹介します。小ネタで恐縮ですが、よろしくお願いします。

## 背景

セキュリティ運用チームでは、セキュリティアラートの管理と対応状況を可視化するため、次のような要件があるとします。

1. 前月発生したインシデントの総数と、未クローズのインシデント数を集計したい
2. 集計結果をSlackで共有し、チーム全体で前月の振り返りを行いたい
3. 実行は毎月5日に自動的に行われるようにしたい

ここでは、Logic Appを用いて、月次スケジューリングを行い、Sentinel のデータに対してKQLクエリを実行します。その結果を整形してSlackにポストする一連のフローを構築します。

## 全体像

1. Logic Appのトリガー：月次スケジューリングトリガーを利用し、毎月1日に処理を開始します。
2. Azure Monitor Logs コネクタを用いて、Sentinelデータに対してKQLクエリを実行します。
3. KQLクエリで、前月に発生したインシデントの総数と未クローズ数を集計します。
4. 集計結果をSlack用に整形し、Slackチャンネルへポストします。

## クエリ例と解説

### 前月のインシデント集計クエリ

下記は、`SecurityIncident`テーブルを用いて、前月のインシデント総数と未クローズインシデント数を取得するためのKQLクエリ例です。

```kql
// 変数定義
let FirstOfLastMonth = startofmonth(ago(1d), -1);
let StartOfThisMonth = startofmonth(ago(1d));
// メインクエリ
SecurityIncident
| where TimeGenerated >= FirstOfLastMonth
| where CreatedTime >= FirstOfLastMonth and CreatedTime < StartOfThisMonth
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| summarize
    TotalIncidents = count(),
    OpenIncidents = countif(Status != "Closed")
| extend
    Message = strcat(
        "前月は合計", tostring(TotalIncidents), "件のアラートが発生し、",
        "そのうち", tostring(OpenIncidents), "件が未クローズです。"
    )
| project Message, TotalIncidents, OpenIncidents
```

### ポイント解説

- `FirstOfLastMonth` および `StartOfThisMonth` は、それぞれ「前月の初日」と「当月の初日」を示す変数です。これにより、前月分のみを抽出する時間範囲が明確になります。
- `arg_max(TimeGenerated, *) by IncidentNumber` は、同一IncidentNumberで最新のレコードを取得し、最終的なインシデントステータスやメタ情報を集約します。
- `summarize count(), countif(...)` で、前月発生分のトータルおよび未クローズ数を取得します。
- `Message`列で、人間がわかりやすい形でまとめのメッセージを作成しています。

このように、`SecurityIncident`テーブルはインシデント更新のたびに記録が追加される形式のため、単純な`count`や`where`句では正確な前月発生インシデント数や未クローズのステータスを把握しにくいことが分かります。  
よって、`summarize`による集約ロジックが必要になります。

## Logic AppとSlack連携

1. Logic Appでのスケジューラ設定  
   Logic Appの「Recurrence」トリガーを使用して、毎月1日に発火するように設定します。

2. Azure Monitor LogsコネクタでKQL実行  
   Logic AppにはAzure Monitor Logsコネクタがあり、ここで前述のKQLクエリを実行します。  
   結果として、前月インシデント総数や未クローズ数などを取得できます。

3. Slackへのポスト処理  
   KQLクエリの結果をもとに、HTTPコネクタやSlackコネクタ(またはWebhook)を用いて、Slackの指定チャンネルにメッセージを投稿します。

   例えば、クエリから取得した`Message`列を、そのままSlackチャンネルにポストすることで、以下のようなメッセージを送れます。

   ```
   前月は合計 XX 件のアラートが発生し、そのうち YY 件が未クローズです。
   ```

## まとめ

- `SecurityIncident`テーブルはインシデントごとに記録が増えるため、集計ロジックが必要になります。
- `summarize` を用いて、前月発生分のみを抽出し、最終的なインシデントカウントや状態を取得できます。
- Logic Appで月次スケジュールを組むことで、定期的にKQLクエリを実行し、結果をSlack通知する自動化が可能です。

これらの手順を踏むことで、毎月のインシデント状況をシームレスに共有し、運用チームでの振り返りや改善活動に役立てることができます。

