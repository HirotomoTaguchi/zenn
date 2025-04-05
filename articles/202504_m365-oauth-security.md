---
title: "Microsoft 365環境におけるOAuthアプリケーションのリスクと対策"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [Microsoft 365] 
published: false
---

OAuthアプリケーションの主要なリスクと Microsoft 365 環境における具体的な対策についてまとめました。もちろん、Microsoft 365 では数年前からOAuthアプリケーションに関するリスク対策のソリューションを提供してきましたが、最近さらにパワーアップしてきたので、そちらにフォーカスしたいと思います。

:::message
本ブログは2025年4月5日時点の情報を元に執筆しています。
:::

## OAuth とは

OAuth は、サードパーティのアプリケーションがユーザーの認証情報を直接扱うことなく、ユーザーの許可のもとで特定のリソースやデータにアクセスするための認可フレームワークです。これにより、ユーザーは自分のパスワードを共有することなく、アプリケーションに限定的なアクセス権を付与できます。^[https://openid-foundation-japan.github.io/rfc6749.ja.html]

![ChatGPT Image 2025年3月31日 19_52_58](https://github.com/user-attachments/assets/e4d90178-8ffb-49ba-88b7-4e4236ed3dc2)

OAuth の発展は主に2つのバージョンがあります。OAuth 1.0は2010年に標準化されましたが、実装の複雑さや課題から、2012年にはより簡素化・改良されたOAuth 2.0が策定されました。現在、Microsoft 365を含む多くのサービスはOAuth 2.0を採用しています。

## Microsoft 365におけるOAuth実装

Microsoft 365 では Entra ID が OAuth 2.0 の基盤を提供しており、ユーザーがアプリにサインインする際に「同意画面」が表示されます。この同意を行うと、同意時に許可した権限において、第三者アプリが Microsoft 365 テナント上の情報にアクセスします。^[https://learn.microsoft.com/ja-jp/entra/architecture/auth-oauth2] 特に、Microsoft GraphはMicrosoft 365のデータへの統一APIとして機能し、OAuthを通じてアクセスされることが多いです。アプリケーションはMicrosoft Graphを介して、メール、予定表、ファイル、チャットなど様々なリソースにアクセスできます。

![image](https://github.com/user-attachments/assets/373a04ef-7cfd-4085-8b9a-1881280022bb)

## OAuth を取り巻く状況

OAuthは便利な技術ですが、適切な管理が行われないと、組織のセキュリティに重大な影響を与える可能性があります。主なリスクは以下のカテゴリに分類できます。

### データ流出リスク

一見無害なアプリが、必要以上の権限を要求し、ユーザーが同意することで、データの過剰共有が起きる可能性があります。例えば、単なるPDF変換ツールが、なぜかメールボックス全体へのアクセス権（Mail.ReadWrite.All）を要求し、ユーザーが気づかずに同意してしまうケースです。ユーザーとしては、Microsoft 365に安全に保管していたと思っていたデータが、いつの間にかサードパーティのアプリに流れている状況も考えられます。

### 同意フィッシング（Consent Phishing）

2020年以降特に増加している攻撃手法で、攻撃者が正規のアプリケーションを装った悪意のあるOAuthアプリケーションを作成し、ユーザーを騙して広範な権限を付与させ情報を搾取します。具体的な事例として、2023年にはAzureとMicrosoft 365をターゲットにした「OiVaVoii」キャンペーンが確認されました。この攻撃では、正規のアプリを装ったフィッシングメールによって、ユーザーが「Files.ReadWrite.All」などの広範な権限を許可してしまい、データ漏洩が発生しました。^[https://www.microsoft.com/security/blog/2023/05/08/detecting-and-preventing-oauth-attacks/]

### 長期的潜伏リスク

OAuthトークンは、一度許可されると明示的に取り消されるまで有効であるため、悪意のあるアプリが長期間（数ヶ月から数年）にわたって環境内に潜伏し続ける可能性があります。これは通常のパスワード変更では無効化されないため、侵害の発見が遅れる原因となります。

### 委任されたアクセスの危険性

特に危険性の高い権限スコープとしては以下が挙げられます。

- Mail.ReadWrite.All: すべてのユーザーのメールボックスへの読み書きアクセス
- Files.ReadWrite.All: すべてのユーザーのOneDriveやSharePointファイルへの読み書きアクセス
- Directory.ReadWrite.All: ディレクトリデータ（ユーザー情報など）の読み書きアクセス
- User.ReadWrite.All: すべてのユーザープロファイルの読み書きアクセス

これらの権限を持つアプリは、実質的にテナント全体に対する広範なアクセス権を持ち、大規模なデータ窃取や権限昇格が可能になります。

### アプリ検証の限界

Microsoft Entra IDでは「確認済み発行元（Verified Publisher）」の仕組みがありますが、これはあくまで発行元のアイデンティティを確認しているだけであり、アプリケーションが安全であることを保証するものではありません。確認済み発行元のアプリでも過剰な権限を要求したり、データを適切に保護しない可能性があります。また、一部の発行元はパブリッシャー検証を経ていないものの、組織内では必要なアプリであるケースもあり、一律のブロックだけでは運用上の課題が生じます。

## Microsoft 365 でできる対策

OAtuth アプリのリスクは Microsoft 365 に限定したものではありませんが、今回は Microsoft 365 に限定してとれる対策を考えてみます。

### 前提：アプリガバナンスの有効化

これから対策の前提として、Defender for Cloud Apps のアプリガバナンスを有効化します。

![image](https://github.com/user-attachments/assets/dc739c80-7da4-47f2-837c-5eb512fe3b1f)

### OAuth アプリの見える化と個別の制御

対策の第一歩として、Microsoft Defender for Cloud Apps にて、OAuth アプリの利用状況を可視化することが考えられます。Microsoft Defender for Cloud Apps は E5 ライセンスなどに含まれるクラウドアプリ保護ソリューションですが、Microsoft 365 で OAuth アプリと接続したら、Microsoft Defender XDR の管理コンソールで一覧化して見ることができます。組織で誰がどのような OAuth アプリを接続しているのかを見るのに非常に適しています。

![image](https://github.com/user-attachments/assets/8b3fa5f4-426b-4b01-94f8-7746ff1f7c93)


また、^[https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/protect-saas-apps-from-oauth-threats-with-attack-path-advanced-hunting-and-more/4395997]

加えて、Defender の Advanced Hunting では、これらの情報をクエリで検索することができるので、リスクの高いアプリのみを抽出して対策を行うことが考え得られます。^[https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-oauthappinfo-table]

### アプリ同意ポリシーの定義

Entra ID では、同意を許可するアプリの条件を設定できます。ユーザーが未承認のアプリに権限を与えるのを防ぐために、ユーザー同意を許可しないように構成することが考えられます。Microsoft Entra管理センター → エンタープライズアプリケーション → 同意とアクセス許可 に移動します。そこで、「アプリケーションのユーザー同意」を「ユーザー同意を許可しない」に設定します。

![image](https://github.com/user-attachments/assets/48708af5-6e4b-431c-82d7-7605a6645996)

また、管理者承認ワークフローを有効にして、ユーザーがアクセス権を与える前に承認を要求するようにします。

![image](https://github.com/user-attachments/assets/08beb0db-e491-442d-aa73-9d7f5d8fe363)

すると、

![image](https://github.com/user-attachments/assets/c9b15221-3b94-4c21-bce1-cbae0e09c64a)


![image](https://github.com/user-attachments/assets/5222ee4f-4839-4b9f-bdf3-87098479a2e6)


### 個別の制御（アクセス権の取り消し）

OAuth アプリに対する個別の制御も重要です。既存アプリを含めて潜在的なリスクを持つアプリに対して、特定のアクセス許可を制限したり、完全に禁止したりすることができます。

Microsoft Defender XDRポータルから「アプリガバナンス」に移動します。「アプリの構成と許可」セクションで、特定のアプリや権限スコープに対する制限ポリシーを作成します。

![image](https://github.com/user-attachments/assets/d1eaedeb-d595-44f1-8153-5353029510a4)

これにより、リスクの高いアプリケーションやアクセス許可をコントロールし、組織データへの不適切なアクセスを防止できます。

![image](https://github.com/user-attachments/assets/aeaac340-bc7b-468f-b727-e9d9e2643937)

### 監視体制

継続的な監視は防御の重要な要素です。Microsoft 365環境におけるOAuthアプリケーションの活動を監視するために、Microsoft Defender for Cloud Apps でアラートポリシーを設定して、不審なOAuthアプリケーションの活動を検出します。



### 対応（攻撃の中断）
万が一、悪意のあるOAuthアプリが検出された場合は、迅速に対応することが重要です。Microsoft Defender の「自動調査と対応」機能を活用することで、検出されたOAuth関連のインシデントに対して自動的に対応することも可能です。この機能は2024年末から強化され、より効果的な保護を提供しています。

## 終わりに

OAuth は便利な一方で、適切な管理なしでは重大なセキュリティリスクとなり得ます。Microsoft 365環境では、アプリガバナンス、同意ポリシー、監視体制、迅速な対応能力を組み合わせることで、これらのリスクを大幅に軽減できます。特に2024年後半から2025年にかけて、MicrosoftはOAuth保護機能を強化しており、これらの新機能を活用することで、組織はより堅牢なセキュリティ体制を構築できます。

ただし、テクノロジだけでは完全な保護はできません。最終的には、ユーザー教育とセキュリティ意識向上トレーニングを継続的に実施し、OAuthアプリケーションのリスクについて組織全体の理解を深めることも重要だと考えています。これらの対策をバランスよく実施することで、OAuthを悪用した攻撃から組織を効果的に守ることができると思いますので、参考になれば幸いです。
