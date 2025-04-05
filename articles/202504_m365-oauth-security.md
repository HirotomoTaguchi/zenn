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

![ChatGPT Image 2025年3月31日 19_52_58](https://github.com/user-attachments/assets/e4d90178-8ffb-49ba-88b7-4e4236ed3dc2)

## OAuth とは

OAuth は、サードパーティのアプリケーションがユーザーの認証情報を直接扱うことなく、ユーザーの許可のもとで特定のリソースやデータにアクセスするための認可フレームワークです。​これにより、ユーザーは自分のパスワードを共有することなく、アプリケーションに限定的なアクセス権を付与できます。Microsoft 365 では Entra ID が OAuth 2.0 の基盤を提供しており、ユーザーがアプリにサインインする際に「同意画面」が表示されます。この同意を行うと、同意時に許可した権限において、第三者アプリが Microsoft 365 テナント上の情報にアクセスします。

![image](https://github.com/user-attachments/assets/373a04ef-7cfd-4085-8b9a-1881280022bb)

## OAuth を悪用したリスク事例

このように便利な機能である一方で、適切な管理が行われないと、以下のような組織のセキュリティに重大な影響を与える可能性があります。一見無害なアプリが、必要以上の権限を要求し、ユーザーが同意することで、データの過剰共有が起きる可能性があります。ユーザーとしては、Microsoft 365 に安全に保管していたと思っていたデータが、いつの間にかサードパーティのアプリに流れている状況も考えられます。また、攻撃者が正規のアプリケーションを装った悪意のあるOAuthアプリケーションを作成し、ユーザーを騙して広範な権限を付与させ情報を搾取する同意フィッシングなどのリスクもあります。

## Microsoft 365 でできる対策

OAtuth アプリのリスクは Microsoft 365 に限定したものではありませんが、今回は Microsoft 365 に限定してとれる対策を考えてみます。

### OAuth アプリの見える化と個別の制御

M356への対策の第一歩として、Microsoft Defender for Cloud Apps にて、OAuth アプリの利用状況を可視化することが考えられます。Microsoft Defender for Cloud Apps は E5 ライセンスなどに含まれるクラウドアプリ保護ソリューションですが、Microsoft 365 で OAuth アプリと接続したら、Microsoft Defender XDR の管理コンソールで一覧化して見ることができます。組織で誰がどのような OAuth アプリを接続しているのかを見るのに非常に適しています。

![image](https://github.com/user-attachments/assets/49c0facb-daf4-4a9b-a7fb-a7713536aa03)

また、

### アプリ同意ポリシーの定義

Entra ID では、同意を許可するアプリの条件を設定できます。確認済み発行元みのアプリのみユーザー同意を許可するなど、素性をベースに管理することが可能です。

### 監視体制



### ユーザー同意を許可しない
ユーザーが未承認のアプリに権限を与えるのを防ぐために、ユーザー同意を許可しないように構成することが考えられます。

1️. Microsoft Entra管理センター → エンタープライズアプリケーション → 同意とアクセス許可 に移動します。
2️. 「アプリケーションのユーザー同意」を「ユーザー同意を許可しない」に設定します。
3. 管理者承認ワークフローを有効にして、ユーザーがアクセス権を与える前に承認を要求するようにします。

## 終わりに

Microsoft 365 環境におけるOAuthアプリケーションのセキュリティは、組織の重要な資産を守る上で不可欠な要素です。これらの対策を組み合わせることで、OAuthを悪用した攻撃から組織を守りながら、必要な業務効率化を実現していきましょう。

## 参考文献
https://openid-foundation-japan.github.io/rfc6749.ja.html

https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/protect-saas-apps-from-oauth-threats-with-attack-path-advanced-hunting-and-more/4395997

https://learn.microsoft.com/ja-jp/entra/architecture/auth-oauth2
