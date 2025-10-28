---
title: "【小ネタ】Logic AppsでRSSを設定したのに息していない件～トリガーが働かない原因と対処～"
emoji: "💻" 
type: "tech" ## tech: 技術記事 / idea: アイデア記事
topics: [Microsoft Teams, Power Automate, Logic Apps] 
published: true
---

今日は Azure Logic Apps で RSS トリガーを設定したのに動かない現象に遭遇したので、備忘録がてらブログにしてみます。

## きっかけ：ニュースを自動収集したいしたい！

とあるネタのニュースを自動検知したくなった私。RSS フィードとLogic Apps を使えば、いい感じにフィルターしつつ、 Teams に通知できるじゃん！と思い立ち、以下のような構成を作成しました。

- トリガー：RSS（`https://www[.]xxx[.]xxx/rss`）
- 条件分岐：キーワードでフィルタ
- アクション②：Teams にメッセージ投稿

## 「息してない」Logic Apps

数時間経っても、何も通知が来ない。Logic Apps の実行履歴を見ても、**トリガーが一度も発火していない**。「え？死んでる？」「息してない？」  そんな気持ちでコードビューを開いてみました。

## 原因は**二重エンコード**

コードビューの `feedUrl` を見てみると、こんな記述がありました。

```json
"feedUrl": "@{encodeURIComponent(encodeURIComponent('https://www.ransomware.live/rss','\n'))}"
```

えっ、`encodeURIComponent` が **2回**！？ しかも `'\n'` って何！？（引数として意味不明）このせいで URL が `https%253A%252F%252F...` という謎の文字列になり、RSS コネクターが正しく読み込めていなかった模様。

## 解決方法

コードビューを開き以下のように修正したら、無事トリガーが息を吹き返しました。

```json
"feedUrl": "https://www[.]xxx[.]xxx/rss"
```

## ついでに確認したこと

- RSS コネクターの接続状態
- RSS フィードの有効性
- Logic Apps の実行履歴 → トリガーが正常に発火していることを確認

## おわりに

Logic Apps は便利だけど、**コードビューの自動補完が罠になることもある**ので要注意。 「息してない」Logic Appsを見つけたら、まずは `feedUrl` をチェックしてみてください！
