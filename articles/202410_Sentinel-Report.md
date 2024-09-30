---
title: "Sentinel Report"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [XXX, XXX] 
published: false
---

```kql
// Step 1: 前月1日から本日までのデータを取得しIncidentNumberでサマライズ
let FirstOfLastMonth = startofmonth(now(), -1);
let StartOfThisMonth = startofmonth(now());
SecurityIncident
| where FirstActivityTime >= FirstOfLastMonth and FirstActivityTime <= now()
| summarize
    EarliestFirstActivityTime = min(FirstActivityTime),
    WasEverClosed = countif(Status == "Closed") > 0
by IncidentNumber
// Step 2: FirstActivityTimeが今月のものを除外
| where EarliestFirstActivityTime < StartOfThisMonth
// Step 3: 前月のインシデント数をカウントし、メッセージを生成
| summarize IncidentCount = count()
| extend Message = strcat("前月は", tostring(IncidentCount), "件のアラートが発生しました。")
| project Message
```

```kql
// Step 1: 前月1日から本日までのデータを取得し、IncidentNumberとTitleでサマライズ
let FirstOfLastMonth = startofmonth(now(), -1);
let StartOfThisMonth = startofmonth(now());
SecurityIncident
| where FirstActivityTime >= FirstOfLastMonth and FirstActivityTime <= now()
| summarize
    EarliestFirstActivityTime = min(FirstActivityTime),
    WasEverClosed = countif(Status == "Closed") > 0
by IncidentNumber
// Step 2: FirstActivityTimeが今月のものを除外
| where EarliestFirstActivityTime < StartOfThisMonth
// Step 3: "Closed" でないレコードをカウントし、数字を出力
| where WasEverClosed == 0
| summarize OpenIncidentCount = count()
// 数字のみを出力
| project OpenIncidentCount
```

```kql
// Step 1: 前月1日から本日までのデータを取得し、IncidentNumberとTitleでサマライズ
let FirstOfLastMonth = startofmonth(now(), -1);
let StartOfThisMonth = startofmonth(now());
SecurityIncident
| where FirstActivityTime >= FirstOfLastMonth and FirstActivityTime <= now()
| summarize
    EarliestFirstActivityTime = min(FirstActivityTime),
    WasEverClosed = countif(Status == "Closed") > 0
by IncidentNumber
// Step 2: FirstActivityTimeが今月のものを除外
| where EarliestFirstActivityTime < StartOfThisMonth
```
