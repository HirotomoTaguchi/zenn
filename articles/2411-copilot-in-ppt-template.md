---
title: "企業パワポテンプレを M365 Copilot in PowerPoint に最適化させる"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [M365 Copilot] 
published: true
---
Copilot in PowerPoint を企業パワポテンプレをCopilotに最適化させる方法が登場したので試してみました。

## 課題感
M365 Copilot のCopilot in PowerPointにおいて特に企業固有のフォーマットやユーザーの意図にアジャストした「いい感じ」の資料作成はまだまだ難しいのが実情です。もちろん、Copilot 登場時点から企業テンプレートを使って、Copilotによるスライド生成は可能でしたが、「違う・・・そうじゃない！」というのが多かったのが実情です。スライドマスタを無視したり、絶妙なチョイスで「自分で作った方が早い」と思ったのは1度や2度ではありません。

![image](https://github.com/user-attachments/assets/bb5bc03c-318a-41fd-b15b-bc48eceb9c7f)
*引用：[Copilot for Microsoft 365 ぶっちゃけどうなん？ - CloudNative Inc. BLOGs](https://blog.cloudnative.co.jp/22728/#co-index-5)*

## 推奨「レイアウト名」でCopilotの精度を上げる
そんな中、Copilot は推奨されるレイアウト名を元に、企業ブランドとコンテンツのニーズをくみ取ってスライドを生成するように機能強化がなされました。もちろん、完璧なものではありませんが、これを活用すると以前よりは高品質なスライド生成をすることを狙ったものです。

仕組みとしては、Copilotによるスライド作成時に、スライドマスターの「レイアウト名」をCopilotが読み取り、その情報を元にコンテンツを当てはめてスライドを生成してくれるとのことです。

![image](https://github.com/user-attachments/assets/f183bcb8-cf7e-4bf2-b18e-892f0f904853)

## テンプレート作成方法
### パターン1. レイアウト名を人力で変更
企業で利用している、パワポのテンプレートにて、**表示タブ**から**スライドマスター**ビューを開きます。その後、スライドマスターのそれぞれのレイアウトにて、右クリックでレイアウト名を変更します。
![image](https://github.com/user-attachments/assets/72037640-ff9f-4c27-ae9b-b4a4769e2ffa)

変更するレイアウト名は以下を参考にしてください。
![image](https://github.com/user-attachments/assets/fbac8b85-eeee-4aab-9c0b-f20bb3dcc176)
*参考：[Keep your presentation on-brand with Copilot](https://support.microsoft.com/en-us/topic/keep-your-presentation-on-brand-with-copilot-046c23d5-012e-49e0-8579-fe49302959fc?preview=true)*

この名前に変更することで、Copilotでスライド作成を指示する際に、レイアウトの名前を考慮してくれるようになります。ちなみに、後述の通り、名前だけではなくて、様々なバリエーションのレイアウトを作っておくことも大事です。

### パターン2. テンプレを利用（移植）
実は今回、Coplotの推奨のレイアウト名が記載されたCopilot in PowerPoint のスターター テンプレートもが[ブログ](https://techcommunity.microsoft.com/blog/microsoft365insiderblog/keep-your-presentations-on-brand-with-copilot-in-powerpoint/4295913)で公開してくれています。

![image](https://github.com/user-attachments/assets/0ee5bf2c-7c89-4713-8d11-3dec93b4eb0e)
*[URL](https://techcommunity.microsoft.com/blog/microsoft365insiderblog/keep-your-presentations-on-brand-with-copilot-in-powerpoint/4295913)*

そのテンプレートを改造するか、レイアウトを「企業で利用している既存のパワポテンプレート」に移植するという手段があります。

移植の方法としては、「企業で利用している既存のパワポテンプレート」と「スターターキット」の両方を開きます。その後、「スターターキット」の方で**表示タブ**から**スライドマスター**ビューを開きます。すると、マイクロソフトが定義した推奨の「レイアウト名」が使われているスライドマスターの一覧を見れます。

![image](https://github.com/user-attachments/assets/5fb496b3-6baf-4995-b542-3ec0aa16499d)

テンプレートに含まれるスターターレイアウトを、新規または既存のテンプレートにコピー＆ペーストします。

![image](https://github.com/user-attachments/assets/315a36b1-2ab0-4e3c-b76f-b0a2f908bf3f)

コピペしたら、それを企業テンプレを使って整形していきます。その際、レイアウト名は元のテンプレートを踏襲するのが肝です。

![image](https://github.com/user-attachments/assets/4e91ea1f-565b-4898-bb90-cf56dad90695)

## Copilotでスライド作成
PowerPointでテンプレートを開き、左上のCopilotアイコンをクリックします。そこで「XXXに関するプレゼンテーションを作成してください」などというプロンプトを用いて、スライド作成を指示します。
![image](https://github.com/user-attachments/assets/c7396a03-fb0b-4e61-9f9b-55d4c08c8d8a)

すると、従来通りスライドが作成されるわけですが、作成される際に、「タイトル」や「コンテンツ」や「結論」といった「レイアウト名」を読み取って、スライドを生成してくれるようです。

![image](https://github.com/user-attachments/assets/7818232b-1a4d-492d-935c-b2b2d3157b8f)

## Tips
### レイアウトの多様性（バリエーション）
マイクロソフトの[ブログ](https://techcommunity.microsoft.com/blog/microsoft365insiderblog/keep-your-presentations-on-brand-with-copilot-in-powerpoint/4295913)によると、レイアウト（プレースホルダ）の多様性を増やしてあげることが、より良い精度への鍵になるとのことです。個人的には特に「コンテンツ」の部分は複数のレイアウトを用意しておくことが大事だなと思っています。そういった意味では、スターターキットを使うのも良いかもしれません。（画像を入れるレイアウトが多く、そのままビジネスでは使いたくないですが、、）

![image](https://github.com/user-attachments/assets/c35003f6-b66d-4b35-9a81-5dcf792124ba)
*[出所](https://techcommunity.microsoft.com/blog/microsoft365insiderblog/keep-your-presentations-on-brand-with-copilot-in-powerpoint/4295913)*

### 日本語対応
ちなみに、レイアウト名は日本語に対応しているようです。早々に対応してくれて、ありがたい限りですね。
![image](https://github.com/user-attachments/assets/4a1dc2f0-e42e-48b3-90aa-379db1d38730)
*[参考](https://support.microsoft.com/en-us/topic/keep-your-presentation-on-brand-with-copilot-046c23d5-012e-49e0-8579-fe49302959fc?preview=true)*

## 終わりに
Copilot in PowerPointは登場当初、多くのユーザーの期待に届かずがっかりされた印象もありましたが、日々改善されています。まだ完璧ではありませんが、日本のビジネスマンが多くの時間を費やしているスライド作成が、さらに効率的になることを期待したいです。

また、個人的な観測範囲では綺麗なスライドを作る人の特徴として、スライドマスタを意識しているという要素があるような気がしています。そういった意味ではこれを機にスライドマスタを見直してみるとよいかもしれません。

## 参考
- [Copilotでプレゼンテーションをブランドイメージに忠実に保ちましょう](https://support.microsoft.com/en-us/topic/keep-your-presentation-on-brand-with-copilot-046c23d5-012e-49e0-8579-fe49302959fc?preview=true)
- [Keep your presentations on brand with Copilot in PowerPoint](https://techcommunity.microsoft.com/blog/microsoft365insiderblog/keep-your-presentations-on-brand-with-copilot-in-powerpoint/4295913?ocid=usoc_TWITTER_M365_spl100006689760691)
