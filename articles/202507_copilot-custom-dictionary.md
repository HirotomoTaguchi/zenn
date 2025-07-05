---
title: "Copilot Custom Dictionary（カスタム辞書）を使ってみる"
emoji: "💻" 
type: "tech" ## tech: 技術記事 / idea: アイデア記事
topics: [copilot, Microsoft 365] 
published: false
---

AI議事録を使っている場合、会社名や製品名が正しく認識されなかったり、社内用語のためAIが文脈を読み取れず議事録の精度が低いケースが多々あります。ましては、私のように活舌が良くないと尚更文字起こしがうまくいかないケースも少なくありません。そんな中、Microsoft 365 CopilotのTeams会議議事録において、これらの問題に対応するための新機能「Copilot Custom Dictionary（カスタム辞書）」が、2025年6-7月にかけて、展開開始されはじめたので、さっそく触ってみました。

:::message
本ブログは2025年7月5日時点の情報を元に執筆しています。
:::

## Copilot Custom Dictionaryとは？

Microsoft 365 CopilotのTeams会議議事録（Intelligent Recap）において、組織固有の用語を正確に認識させるための機能です。製品名、プロジェクト名、専門用語を自社の用語を登録しておくことで、会議中の議事録の精度を高めてくれます。

## 対象となる会議

- スケジュールされたTeams会議
- タウンホール
- ウェビナー

:::message alert
※現時点では1対1の通話やアドホック通話は対象外とのことです。
:::

## 設定方法

### 前提条件

1. **管理者権限**: 全体管理者またはAI管理者
2. **ライセンス**: Microsoft 365 Copilotライセンス
3. **プレビュー参加**: Teams パブリックプレビュー プログラムへの参加

### 設定手順

#### 1. 管理センターへアクセス
[M365管理センター](https://admin.microsoft.com) にサインインし、左メニューから「Copilot」→「設定」→「その他の設定」を選択します。

![スクリーンショット 2025-07-05 065819](https://github.com/user-attachments/assets/345303dd-dd57-475b-9d9e-c734c2b577bd)

#### 2. テンプレートをダウンロード

‎Copilot‎ Custom Dictionaryを選択し、Uploadをクリックすると、テンプレートが表示されるので、「CSV template with header only」ファイルをダウンロードします。

![スクリーンショット 2025-07-05 072657](https://github.com/user-attachments/assets/483c4c5d-a1da-4f65-9457-7de78acafe2b)

#### 3. CSVファイルを編集

テンプレートを開いて、以下の設定例のように以下の形式で用語を登録します。どのように登録したらいいかは試行錯誤中なので、いい感じになるパターンを見つけたらアップデートします。

```csv
Term (required),Sounds like,Long form of the term (for acronyms),Definition and context
IS,aiesu,情報システム部,社内の情報システムを管理する部署
情シス,zyousisu,情報システム部,社内の情報システムを管理する部署
品証,hinsyou,品質保証部,品質保証部の略称
DX,di-ekkusu,デジタルトランスフォーメーション推進部,社内のデジタルトランスフォーメーションを推進する部署
経企,keiki,経営企画部,経営企画部の略称
コパ活,kopakatu,Copilot活用,Copilot活用を広めていくための取り組み
GSP,gi-esu-pi-,Global Security Policy,グループグローバルで定められたセキュリティ規定
コパソウ,kabushikigaisha copilot souken,株式会社copilot創研,主要取引先企業名
ポンチ絵,ponchie,,会議などで使用される簡単な概念図やスケッチ
なるはや,naruhaya,なるべく早く,「なるべく早く」の略語。緊急性を伝える際に使用
よしなに,yoshinani,,「いい感じに」「適切に」という意味。相手に裁量を任せる際に使用
あいみつ,aimitsu,相見積もり,複数の業者から見積もりを取り、比較検討すること
たたき台,tatakidai,,議論のベースとなる初版の草案や提案
サマる,samaru,要約する,要約する（summarize）の和製英語
魁プロジェクト,sakigake purojekuto,,新規事業の社内コードネーム
蒼天ソリューション,souten soryuushon,,架空の主力製品・サービス名
Zenithシステム,zenisu shisutemu,,社内で開発された基幹業務システム名
KAIZEN会議,getsuji teirei kaizen kaigi,KAIZEN会議,毎月行われる業務改善のための定例会議
```

:::message alert
Microsoft Learn^[[Manage custom dictionaries for Microsoft Teams meetings and events](https://learn.microsoft.com/en-us/microsoftteams/copilot-custom-dictionary)] を読む限り、Sounds like と Long form of the term (for acronyms) は現時点では活用されず、アップデート後に使えるようになるように読めます。また、日本語辞書において、Sounds like を記載する際にローマ字（例：GSPだったら「gi-esu-pi-」と記載するか日本語（ジーエスピー）と記載するのが良いかは調査中です。わかり次第アップデートします。）
:::

#### 4. アップロード
CSVファイルを「CSV UTF-8」形式で保存し、管理センターでファイルをアップロードします。その際、対象言語を選択（日本語など）します。

### 反映時間

設定完了後、最大24時間で全テナントに反映されます。

## 試してみる

正直音声系のタスクは個人ではなかなか性能のテストを実施しずらいなというのが本音ではありますが、例えば「コパ活」という言葉を登録しておいた際、僕が活舌が悪く「子爆発/子爆かつ」と認識されるようなことが多かったように思いますが、その辺をうまくとらえてくれるようになったよう風な感想です。また、組織略称（例：経営企画部→経企、品質保証部→品証）に強くなったようにも思えますが、このテストケースではBefore/Afterが地味だったので、すごい実感が得られたかというとそうではないです。

大企業で社内用語が多くなればなるほど力を発揮すると思うので、是非お手元で試していただけると幸いです。

## 制限事項

### 技術的制限

- **最大500語**: 1つの辞書ファイル（言語毎）あたり500語までの制限があります。
- **管理者のみ更新**: 一般ユーザーは編集できず、管理権限を保有している必要があります。
- **言語ごとに1ファイル**: 同じ言語の複数辞書は不可
- **完全上書き**: 更新時は既存辞書を完全に置き換え
- **グループやユーザー指定不可**: 現時点ではグループやユーザーなどで対象範囲を指定することはできません。

### 対象外の会議

- 1対1の通話
- スケジュールされていないグループ通話
- Copilotライセンスを持たないユーザーが開始した会議

## Copilot Tuning とは別物なので注意

2025年5月のMicrosoft Buildにて発表された「Copilot Tuning^[[XXX](https://techcommunity.microsoft.com/blog/microsoft365copilotblog/introducing-microsoft-365-copilot-tuning/4414762)]」と本機能は別機能です。Copilot Tuningは現在、Microsoft 365 Copilotを5000ライセンス以上保持している方を対象とした早期プレビューでのみ利用できます。

## まとめ

Microsoft 365 Copilotへの投資を最大化するため、カスタム辞書の導入を検討いただけたら幸いです。正確な文字起こしが、より高度なAI機能の土台となります。
