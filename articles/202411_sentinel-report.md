---
title: "Sentinel Report"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [Sentinel] 
published: false
---

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

```kql
// Step 1: 前月1日から本日までのデータを取得し、IncidentNumberとTitleでサマライズ
let FirstOfLastMonth = startofmonth(now(), -1);
let StartOfThisMonth = startofmonth(now());
SecurityIncident
| where CreatedTime >= FirstOfLastMonth and CreatedTime <= now()
| summarize
    EarliestCreatedTime = min(CreatedTime),
    WasEverClosed = countif(Status == "Closed") > 0
by IncidentNumber
// Step 2: CreatedTimeが今月のものを除外
| where EarliestCreatedTime < StartOfThisMonth
```
