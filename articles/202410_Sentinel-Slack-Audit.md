---
title: "Slack Audit"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [XXX, XXX] 
published: false
---

```kql
SlackAudit_CL
| where TimeGenerated > ago(24h)
| where actor_user_name_s != "Slackbot"
| where action_s == "file_uploaded"
| where not(entity_file_name_s endswith ".png" or entity_file_name_s endswith ".jpg" or entity_file_name_s endswith ".jpeg" or entity_file_name_s endswith ".mov")
| summarize
    count_of_uploads = count(),
    files = make_set(entity_file_title_s, 100),
    users = make_set(actor_user_name_s, 100),
    user_emails = make_set(actor_user_email_s, 100)
| project
    TimeGenerated = now(),
    count_of_uploads,
    files,
    users,
    user_emails,
    Title = "非画像ファイルアップロードを検出",
    Description = strcat("過去24時間で ", count_of_uploads, " 件の非画像ファイルアップロードが検出されました。")
```
