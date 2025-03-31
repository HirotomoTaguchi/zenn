---
title: "Microsoft 365環境におけるOAuthアプリケーションのリスクと対策"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [Microsoft 365] 
published: false
---

本記事では、Microsoft 365環境におけるOAuthアプリケーションの主要なリスクと、それに対する具体的な対策について解説します。特に、最近増加しているOAuthを悪用した攻撃手法と、それらを防ぐために考えられる対策について言及します。

## OAuthとは

![ChatGPT Image 2025年3月31日 19_52_58](https://github.com/user-attachments/assets/e4d90178-8ffb-49ba-88b7-4e4236ed3dc2)

OAuth は、サードパーティのアプリケーションがユーザーの認証情報を直接扱うことなく、ユーザーの許可のもとで特定のリソースやデータにアクセスするための認可フレームワークです。​これにより、ユーザーは自分のパスワードを共有することなく、アプリケーションに限定的なアクセス権を付与できます。Microsoft 365 では Entra ID が OAuth 2.0 の基盤を提供しており、ユーザーがアプリにサインインする際に「同意画面」が表示されます。

![image](https://github.com/user-attachments/assets/373a04ef-7cfd-4085-8b9a-1881280022bb)

この同意を行うと、同意時に許可した権限において、第三者アプリが Microsoft 365 テナント上の情報にアクセスします。

## OAuth を悪用したリスク事例

このように便利な機能である一方で、適切な管理が行われないと、以下のような組織のセキュリティに重大な影響を与える可能性があります。一見無害なアプリが、必要以上の権限を要求し、ユーザーが同意することで、データの過剰共有が起きる可能性があります。また、攻撃者が正規のアプリケーションを装った悪意のあるOAuthアプリケーションを作成し、ユーザーを騙して広範な権限を付与させる同意フィッシングなどのリスクもあります。

## Microsoft 365 でできる対策

OAtuth アプリのリスクは Microsoft 365 に限定したものではありませんが、今回は Microsoft 365 に限定してとれる対策を考えてみます。

### 前提条件
- 

### 1. OAuth アプリの見える化 & 管理

M356への対策の第一歩として、Microsoft Defender for Cloud Apps にて、OAuth アプリの利用状況を可視化することが考えられます。

![image](https://github.com/user-attachments/assets/c5953c15-578c-4172-8c8e-54f060545068)

### 2. アプリ同意ポリシーの定義

Entra ID では、同意を許可するアプリの条件を設定できます。確認済み発行元みのアプリのみユーザー同意を許可するなど、素性をベースに管理することが可能です。

### 3. 条件付きアクセス

Token Protection や CAE (続行的アクセス評価)を組み合わせ、不正なトークン利用を検知・無効化することが可能です。

### 4. ユーザー教育と監視体制

OAuth 同意のリスクを理解させ、見返しがつくようなアプリへの同意を抵抗するよう教育を行いましょう。同時に Entra ID のログや Defender からのアラートを添えて監視を強化します。

## 終わりに

Microsoft 365 環境におけるOAuthアプリケーションのセキュリティは、組織の重要な資産を守る上で不可欠な要素です。これらの対策を組み合わせることで、OAuthを悪用した攻撃から組織を守りながら、必要な業務効率化を実現していきましょう。

## 参考文献
https://openid-foundation-japan.github.io/rfc6749.ja.html

https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/protect-saas-apps-from-oauth-threats-with-attack-path-advanced-hunting-and-more/4395997

https://learn.microsoft.com/ja-jp/entra/architecture/auth-oauth2
