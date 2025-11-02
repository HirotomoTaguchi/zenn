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

![](https://github.com/user-attachments/assets/7aa40c01-bfdb-4c80-9711-b8b11715b4c5)


## 「息してない」Logic Apps

数時間経っても、何も通知が来ない。Logic Apps の実行履歴(Run History)を見ても、トリガーが一度も発火していない...「え？息してない？」そんな気持ちで調べてみました。

## 原因は**二重エンコード**

トリガー履歴(Triger History)を確認すると、トリガーが失敗していることが確認されました。

![](https://github.com/user-attachments/assets/6e6d1918-601d-473b-83fd-27c258d66be9)

入力のエラーを見てみると、URL が `https%253A%252F%252F...` という謎の文字列となっています。

![](https://github.com/user-attachments/assets/a9a8926b-ba71-4387-a9b2-272c254c726e)

どうやら入力部分ががおかしいと思い、コードビューの `feedUrl` を見てみると、こんな記述がありました。

```json
"feedUrl": "@{encodeURIComponent(encodeURIComponent('https://www[.]xxx[.]xxx/rss','\n'))}"
```

![](https://github.com/user-attachments/assets/db4678ce-1dcc-49fc-a3d6-e3ed1dd07230)

えっ、`encodeURIComponent` が **2回**！？ しかも `'\n'` って何！？（引数として意味不明）このせいで URL が `https%253A%252F%252F...` という謎の文字列になり、RSS コネクターが正しく読み込めていなかった模様です。僕はロジックアプリデザイナーにURLを打ち込んだだけなのに...

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

Logic Apps は便利だけど、ロジックアプリデザイナーで作成した場合の、**コードビューの自動補完が罠になることもある**ので要注意。 「息してない」Logic AppsのRSSを見つけたら、 `feedUrl` をチェックしてみてください！
