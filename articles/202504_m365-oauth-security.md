---
title: "Microsoft 365環境におけるOAuthアプリケーションのリスクと対策"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [Microsoft 365] 
published: false
---

Microsoft 365 では数年前からOAuthアプリケーションに関するリスク対策のソリューションを提供してきましたが、最近さらにパワーアップしてきたので改めてまとめてみました。

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

OAuthは便利な技術ですが、適切な管理が行われないと、組織のセキュリティに重大な影響を与える可能性があります。

### データ流出リスク

代表的なリスクがデータ流出です。一見無害なアプリが、必要以上の権限を要求し、ユーザーが同意することで、データの過剰共有が起きる可能性があります。例えば、単なるPDF変換ツールが、なぜかメールボックス全体へのアクセス権（Mail.ReadWrite.All）を要求し、ユーザーが気づかずに同意してしまうケースです。ユーザーとしては、Microsoft 365に安全に保管していたと思っていたデータが、いつの間にかサードパーティのアプリに流れている状況も考えられます。

### 委任されたアクセスの危険性

委任されたアクセス範囲が広く、アプリが悪用された場合に被害を受けてしまうリスクがあります。特に危険性の高い権限スコープとしては以下が挙げられます。これらの権限を持つアプリは、実質的にテナント全体に対する広範なアクセス権を持ち、大規模なデータ窃取や権限昇格が可能になります。

- Mail.ReadWrite.All: すべてのユーザーのメールボックスへの読み書きアクセス
- Files.ReadWrite.All: すべてのユーザーのOneDriveやSharePointファイルへの読み書きアクセス
- Directory.ReadWrite.All: ディレクトリデータ（ユーザー情報など）の読み書きアクセス
- User.ReadWrite.All: すべてのユーザープロファイルの読み書きアクセス


### 長期的潜伏リスク

OAuthトークンは、一度許可されると明示的に取り消されるまで有効であるため、悪意のあるアプリが長期間（数ヶ月から数年）にわたって環境内に潜伏し続ける可能性があります。これは通常のパスワード変更では無効化されないため、侵害の発見が遅れる原因となります。また、利用しなくなったOAuthアプリ連携を解除せずに放置しておくと、そのアプリが将来的に侵害された場合に、連携されたアカウント情報が悪用されるリスクが残ります。

### 同意フィッシング（Consent Phishing）攻撃

2020年以降特に増加している攻撃手法で、攻撃者が正規のアプリケーションを装った悪意のあるOAuthアプリケーションを作成し、ユーザーを騙して広範な権限を付与させ情報を搾取します。具体的な事例として、2023年にはAzureとMicrosoft 365をターゲットにした「OiVaVoii」キャンペーンが確認されました。この攻撃では、正規のアプリを装ったフィッシングメールによって、ユーザーが広範な権限を許可してしまい、アカウントの乗っ取りが発生しました。^[https://www.proofpoint.com/us/blog/cloud-security/oivavoii-active-malicious-hybrid-cloud-threats-campaign]

### アプリ検証の限界

Microsoft Entra ID では「確認済み発行元（Verified Publisher）」の仕組みがありますが、これはあくまで発行元のアイデンティティを確認しているだけであり、アプリケーションが安全であることを保証するものではありません。確認済み発行元のアプリでも過剰な権限を要求したり、データを適切に保護しない可能性があります。また、一部の発行元はパブリッシャー検証を経ていないものの、組織内では必要なアプリであるケースもあり、一律のブロックだけでは運用上の課題が生じます。

![image](https://github.com/user-attachments/assets/1abb292f-e61a-4556-bc7d-fa458ec91dfe)
*出所：[発行者の確認](https://learn.microsoft.com/ja-jp/entra/identity-platform/publisher-verification-overview?utm_source=chatgpt.com)*

## Microsoft 365 でできる対策

OAtuth アプリのリスクは Microsoft 365 に限定したものではありませんが、今回は Microsoft 365 に限定してとれる対策を考えてみます。

### 前提：アプリガバナンスの有効化

これから対策の前提として、Defender for Cloud Apps のアプリガバナンスを有効化します。

![image](https://github.com/user-attachments/assets/dc739c80-7da4-47f2-837c-5eb512fe3b1f)

### OAuth アプリの見える化と個別の制御

対策の第一歩として、Microsoft Defender for Cloud Apps にて、OAuth アプリの利用状況を可視化することが考えられます。Microsoft Defender for Cloud Apps は E5 ライセンスなどに含まれるクラウドアプリ保護ソリューションですが、Microsoft 365 で OAuth アプリと接続したら、Microsoft Defender XDR の管理コンソールで一覧化して見ることができます。組織で誰がどのような OAuth アプリを接続しているのかを見るのに非常に適しています。

![image](https://github.com/user-attachments/assets/8b3fa5f4-426b-4b01-94f8-7746ff1f7c93)


また、組織のセキュリティリスク（特に攻撃対象領域や脆弱性）を把握し、優先順位をつけて対策を講じるためのソリューションである「Microsoft Security Exposure Management」のAttack Surface Map を使用すると、お客様は、アプリの所有者やアクセス許可レベルなど、OAuth アプリケーションへの組織の接続を視覚化できるようになるそうです。^[https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/protect-saas-apps-from-oauth-threats-with-attack-path-advanced-hunting-and-more/4395997] （僕の手元には来ていない）これらを使うと、影響範囲を気にしながら、優先度の高い対策を考えるインプットとなると思います。

![image](https://github.com/user-attachments/assets/3cc30760-eec8-474b-a795-b7d4c006a5cc)

加えて、Defender XDR の Advanced Hunting では、2025年4月よりこれらの情報をクエリで検索することができるようになったので、リスクの高いアプリのみを抽出して対策を行うことが考え得られます。^[https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-oauthappinfo-table]

```kql
OAuthAppInfo
| where AppStatus == "Enabled"
| where PrivilegeLevel == "High"
| where VerifiedPublisher == "{}" and AppOrigin == "External"
```

![image](https://github.com/user-attachments/assets/936eadd7-55c9-4f49-aa96-0216ccd2fbca)

### アプリ同意ポリシーの定義

Entra ID では、同意を許可するアプリの条件を設定できます。ユーザーが未承認のアプリに権限を与えるのを防ぐために、ユーザーに勝手な同意を許可しないように構成することが考えられます。[Microsoft Entra管理センター] > [エンタープライズアプリケーション] > [同意とアクセス許可] に移動します。そこで、「アプリケーションのユーザー同意」を「ユーザー同意を許可しない」に設定します。

![image](https://github.com/user-attachments/assets/48708af5-6e4b-431c-82d7-7605a6645996)

また、管理者承認ワークフローを有効にして、ユーザーがアクセス権を与える前に承認を要求するようにします。

![image](https://github.com/user-attachments/assets/173f720b-84d3-487f-a486-b439da44d999)

すると、ユーザーがOAuthを設定しようとした際に、管理者に承認ワークフローを依頼する画面が表示され、勝手に同意することができなくなります。

![image](https://github.com/user-attachments/assets/08beb0db-e491-442d-aa73-9d7f5d8fe363)

管理者には以下のような通知が来るので、許可をして初めてユーザーはアプリを利用することができます。

![image](https://github.com/user-attachments/assets/c9b15221-3b94-4c21-bce1-cbae0e09c64a)


### 個別の制御（アクセス権の取り消し）

OAuth アプリに対する個別の制御も重要です。既存アプリを含めて潜在的なリスクを持つアプリに対して、特定のアクセス許可を制限したり、完全に禁止したりすることができます。

Microsoft Defender XDRポータルから「アプリガバナンス」に移動します。「アプリの構成と許可」セクションで、特定のアプリや権限スコープに対する制限ポリシーを作成します。

![image](https://github.com/user-attachments/assets/d1eaedeb-d595-44f1-8153-5353029510a4)

これにより、リスクの高いアプリケーションやアクセス許可をコントロールし、組織データへの不適切なアクセスを防止できます。

![image](https://github.com/user-attachments/assets/aeaac340-bc7b-468f-b727-e9d9e2643937)

### 監視体制

継続的な監視は防御の重要な要素です。Microsoft 365環境におけるOAuthアプリケーションの活動を監視するために、Microsoft Defender for Cloud Apps のアプリガバナンスでアラートポリシーを設定して、不審なOAuthアプリケーションの活動を検出します。アプリガバナンスには、デフォルトで監視のポリシーが設定してあるので、まずはそれらを利用しつつ、それらを参考にしながらポリシーを磨き上げていくことが重要です。

![image](https://github.com/user-attachments/assets/38ca0783-29c5-4af0-9c29-d6e4454116d5)

### 対応（自動攻撃中断）

Microsoft Defender XDRは「自動攻撃中断」機能^[https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption?view=o365-worldwide]を提供しています。​この機能は、OAuthアプリに限った話ではなく、Endpoint/Identity/Office 365（メール）/Cloud App 等、Microsoft Defender XDR 全体シグナルを最大限に活用しながら、AIと機械学習を活用して攻撃者の意図を分析し、リアルタイムでデバイスの隔離、ユーザーアカウントの無効化などの対応を自動的に実行する機能です。 ​これにより、攻撃の進行を迅速に阻止し、被害の拡大を防ぐことが可能となります。

そんな、自動攻撃中断ですが、2025年3月に悪意のあるOAuthアプリの無効化というアクションが含まれると発表がありました。 ^[https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/defending-against-oauth-based-attacks-with-automatic-attack-disruption/4384381] もちろん、必ず中断してくれるとは限らないので、前段で紹介したような対策は必要となりますが、最後の最後やられないための命綱として、この機能を有効化しておくことは非常に有意義だと思います。詳しい有効化方法はMSのドキュメントをご覧ください。^[https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption?view=o365-worldwide]

## 終わりに

OAuth は便利な一方で、適切な管理なしでは重大なセキュリティリスクとなり得ます。Microsoft 365環境では、アプリガバナンス、同意ポリシー、監視体制、攻撃の中断などのうち適切なものを組み合わせることで、これらのリスクを大幅に軽減できます。特に2024年後半から2025年にかけて、MicrosoftはOAuth保護機能を強化しており、これらの新機能を活用することで、組織はより堅牢なセキュリティ体制を構築できます。

ただし、テクノロジだけでは完全な保護はできません。最終的には、ユーザー教育とセキュリティ意識向上トレーニングを継続的に実施し、OAuthアプリケーションのリスクについて組織全体の理解を深めることも重要だと考えています。これらの対策をバランスよく実施することで、OAuthを悪用した攻撃から組織を効果的に守ることができると思いますので、参考になれば幸いです。
