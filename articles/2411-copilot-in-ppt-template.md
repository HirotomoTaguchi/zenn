---
title: "企業パワポテンプレを Copilot in PowerPoint Copilot に最適化させる"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [M365 Copilot] 
published: true
---
Copilot in PowerPoint のスターター テンプレートで企業パワポテンプレをCopilotに最適化させる方法が登場したので試してみました。

## 課題感
M365 Copilot のCopilot in PowerPointにおいて特に企業固有のフォーマットやユーザーの意図にアジャストした「いい感じ」の資料作成はまだまだ難しいのが実情です。もちろん、Copilot登場時点から企業テンプレートを使って、Copilotによるスライド生成は可能でしたが、「違う・・・そうじゃない！」というのが多かったのが実情です。スライドマスタを無視したり、絶妙なチョイスをして自分で作った方がいいと思ったのは1度や2度ではありません。

![image](https://github.com/user-attachments/assets/bb5bc03c-318a-41fd-b15b-bc48eceb9c7f)
*引用：[Copilot for Microsoft 365 ぶっちゃけどうなん？ - CloudNative Inc. BLOGs](https://blog.cloudnative.co.jp/22728/#co-index-5)*

## 推奨「レイアウト名」でCopilotの精度を上げる
そんな中、推奨されるレイアウト名を元に、Copilot が企業ブランドとコンテンツのニーズに合わせてスライドを生成するための新機能が出てきました。また、それに付随して推奨のレイアウト名が記載されたCopilot in PowerPoint のスターター テンプレートが発表されました。もちろん、完璧なものではありませんが、これを活用すると以前よりは高品質なスライド生成が可能となります。

仕組みとしては、Copilotによるスライド作成時にスライドマスターの「レイアウト名」をCopilotが読み取り、その情報を元にコンテンツを当てはめてスライドを生成してくれるとのことです。

![image](https://github.com/user-attachments/assets/fbac8b85-eeee-4aab-9c0b-f20bb3dcc176)

## 事前準備
今回、企業専用のテンプレートを作る上で必要なものは以下です。
- 企業で利用している既存のパワポテンプレート
- マイクロソフトが[ブログ](https://techcommunity.microsoft.com/blog/microsoft365insiderblog/keep-your-presentations-on-brand-with-copilot-in-powerpoint/4295913)で公開しているスターターキット（なくてもできるがあった方が作りやすい。）

## テンプレート作成方法（パターン①）
事前準備で用意した「企業で利用している既存のパワポテンプレート」と「スターターキット」の両方を開きます。まず、「スターターキット」の方で**表示タブ**から**スライドマスター**ビューを開きます。すると、マイクロソフトが定義した推奨の「レイアウト名」が使われているスライドマスターの一覧を見れます。

![image](https://github.com/user-attachments/assets/5fb496b3-6baf-4995-b542-3ec0aa16499d)

テンプレートに含まれるスターターレイアウトを、新規または既存のテンプレートにコピー＆ペーストします。

![image](https://github.com/user-attachments/assets/315a36b1-2ab0-4e3c-b76f-b0a2f908bf3f)

コピペしたら、それを企業テンプレを使って整形していきます。その際、レイアウト名は元のテンプレートを踏襲するのが肝です。

![image](https://github.com/user-attachments/assets/4e91ea1f-565b-4898-bb90-cf56dad90695)

## テンプレート作成方法（パターン②）
既に、かっちりとしたテンプレートがある場合は、スライドマスターを開き、右クリックで、レイアウト名を変更する形でも大丈夫です。
![image](https://github.com/user-attachments/assets/72037640-ff9f-4c27-ae9b-b4a4769e2ffa)

## Copilotでテンプレートを検証
PowerPointでテンプレートを開き、左上のCopilotアイコンをクリックします。そこで「XXXに関するプレゼンテーションを作成してください」などというプロンプトを用いて、スライド作成を指示します。
![image](https://github.com/user-attachments/assets/c7396a03-fb0b-4e61-9f9b-55d4c08c8d8a)

すると、従来通りスライドが作成されるわけですが、作成される際に、「タイトル」や「コンテンツ」や「結論」といった「レイアウト名」を読み取って、スライドを生成してくれるようです。

![image](https://github.com/user-attachments/assets/7818232b-1a4d-492d-935c-b2b2d3157b8f)

## おまけ（日本語対応）
ちなみに、レイアウト名は日本語に対応しているようです。早々に対応してくれて、ありがたい限りですね。
![image](https://github.com/user-attachments/assets/4a1dc2f0-e42e-48b3-90aa-379db1d38730)
*[参考](https://support.microsoft.com/en-us/topic/keep-your-presentation-on-brand-with-copilot-046c23d5-012e-49e0-8579-fe49302959fc?preview=true)*

## 終わりに
Copilot in PowerPointは登場当初、多くのユーザーの期待に届かずがっかりされた印象もありましたが、日々改善されています。まだ完璧ではありませんが、日本のビジネスマンが多くの時間を費やしているスライド作成が、さらに効率的になることを期待したいです。

## 参考
- [Copilotでプレゼンテーションをブランドイメージに忠実に保ちましょう](https://support.microsoft.com/en-us/topic/keep-your-presentation-on-brand-with-copilot-046c23d5-012e-49e0-8579-fe49302959fc?preview=true)
- [Keep your presentations on brand with Copilot in PowerPoint](https://techcommunity.microsoft.com/blog/microsoft365insiderblog/keep-your-presentations-on-brand-with-copilot-in-powerpoint/4295913?ocid=usoc_TWITTER_M365_spl100006689760691)
