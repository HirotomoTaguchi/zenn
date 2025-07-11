---
title: "Microsoft Security Copilot AgentのEntra 条件付きアクセス最適化エージェントを使ってみる"
emoji: "🛡" 
type: "tech" ## tech: 技術記事 / idea: アイデア記事
topics: [Microsoft Entra, Security Copilot, Microsoft Defender, Security]
published: true
---

Microsoft Security CopilotのMicrosoft Entra 条件付きアクセス最適化エージェントを使ってみたので、簡単ですがまとめてみました。

:::message alert
本ブログは2025年6月21日時点の情報を元に執筆しています。また、本ブログには**Limited** Public Previewの内容が含まれています。テナントによって利用の可否が異なりますのでご了承ください。加えて、継続利用を想定しない検証利用の場合は、Security CopilotのリソースSCUは忘れずに消しましょう。
:::

## サマリー
 - 大企業の条件付きアクセスポリシーは、M\&Aや組織変更のたびに増殖・複雑化し、手動での管理は限界に達しがちです。これにより、意図しないセキュリティホールが生まれるリスクがあります。
 - 「条件付きアクセス最適化エージェント」は、AIが条件付きアクセスを継続的にレビューし、ポリシーの「穴（MFA保護されていないユーザー等）」や「重複」を自動で検出し、管理者に具体的な改善策を提案します。
 - 現時点では分析の観点は限定的ですが、観点が拡大すればポリシー管理の属人化を防ぎ、より自律的で高度なセキュリティ運用を実現する第一歩として非常に有望だと感じました。

## 魔境と化すエンプラの条件付きアクセス

Microsoft Entra の条件付きアクセスはセキュリティやアクセス制御における礎です。しかし、組織が成長するにつれて、そのポリシーは増殖し、魔境と化すことが少なくありません。特にグループ会社が単一のMicrosoft 365テナントを共有する大企業グループにおいて顕著です。個別のプロジェクト、一時的なニーズ、あるいは異なるチームによって作成されたポリシーは、その役割を終えても整理されることなく放置されがちです。

数十人規模の会社ではこのようなことは起こりにくいですが、エンタープライズではポリシー作成の制限値（195個^[Microsoft Entra サービスの制限と制約](https://learn.microsoft.com/ja-jp/entra/identity/users/directory-service-limits-restrictions)）に近いポリシーが組まれ、ポリシーが冗長化・競合・穴だらけになることがあります。多くの管理者がPowerShellスクリプトやエクセルを用いた手作業での監査に頼っていますが、関係者が多いとこれは時間と手間がかかるのでしんどいのが実情です。

## 条件付きアクセス最適化エージェントでどうにかできないのか？

このような深刻な課題に対し、Microsoftは2025年に「Microsoft Security Copilot 条件付きアクセス 最適化エージェント^[Microsoft Security Copilot agents overview](https://learn.microsoft.com/en-us/copilot/security/agents-overview)」を繰り出してきました。Microsoft Security Copilot^[Microsoft Security Copilot](https://learn.microsoft.com/en-us/copilot/security/)は、2023年に発表された生成AIベースのセキュリティ支援ツールですが、MicrosoftはさらにこのCopilotを発展させ、特定の任務を自動化するSecurity Copilot **Agent**を導入してきたものです。

![image](https://github.com/user-attachments/assets/1a761d09-5024-427a-9a88-87da0ae9a088)
*^[マイクロソフト、Microsoft Security Copilot エージェントと AI 向けの新しい保護機能を発表](https://www.microsoft.com/en-us/security/blog/2025/03/24/microsoft-unveils-microsoft-security-copilot-agents-and-new-protections-for-ai/?msockid=0d4bd66716e762e62137c358170d6324)*

Microsoft Security Copilot Agentでは、プロンプトありきだった従来のSecurity Copilotとは異なり、Copilotがバックグラウンドで自律的に特定分野のタスクを処理します。他にも、フィッシングメール対応に特化した「Defenderのフィッシングトリアージエージェント」や、データ漏洩防止におけるアラートの重要度判断を行う「Purviewのアラートトリアージエージェント」など、複数のエージェントがMicrosoftから発表されています。

## 使ってみる

本機能を利用するには、Microsoft Entra ID P1以上に加え、Azure上でMicrosoft Security Copilotのライセンス（Security Compute Units - SCU） が必要です。まずは、AzureでSCUをデプロイします。すると、Entraの画面上にエージェントの画面が出現します。

![image](https://github.com/user-attachments/assets/a675710c-fb83-45fb-b03f-8c88ac82ee8f)

:::message
現時点では **Limited** Public Previewであるため、全てのテナントで利用できるわけではなく、残念ながら使えないテナントもあります。Agentが出現しない方は順番が回ってくるまでお待ちください。
:::

有効化すると、エージェントは24時間ごとに自動で条件付きアクセスポリシーをスキャンし、多要素認証（MFA）等が適用されていないユーザーやアプリなどの「保護の穴」がないかを評価します。

![image](https://github.com/user-attachments/assets/c7494f31-28d4-4ff7-ba4d-a49d2259cc1c)

問題が見つかると、Copilotのホーム画面に一覧化されます。提案をクリックすると、「{ユーザー}はMFAで保護されていないです。これらのユーザーを対象とする新しいポリシーを作成しますか？」といった具体的な改善案が表示され、ワンクリックでレポート専用モード のポリシーを作成できます。

![image](https://github.com/user-attachments/assets/e2e8657b-167b-4567-bbe8-ad11970d7da1)
*提案の一覧*

![image](https://github.com/user-attachments/assets/332572c2-1af6-41c2-ac04-0f247ff43a91)
*ここではサインインの際にリスクが高いと判断された場合にMFAを実施するポリシーがレコメンドされています*

:::message
エージェントという名前的になんでもやってくれそうな気もしますが、Security Copilot Agent は既存のポリシーを勝手に変更したり、承認なしに新しいポリシーを有効にしたりすることはありません。あくまで管理者のレビューと承認を前提とした「人間中心（Human-in-the-loop）」の設計になっています。
:::

## 使ってみてどうだったのか？

### ユーザー体験（フロー）は良いと感じた

有効化から提案の受け取り、ポリシー作成までの一連の流れは非常にスムーズです。管理者は複雑な操作をする必要がなく、AIからの提案を確認・評価します。確認した後、クリックするだけでポリシーが作成されます。

![image](https://github.com/user-attachments/assets/2a996bea-b8ed-4479-a5e2-1928463674f7)
*サンプルがちょっとわかりにくいですが「test」という名称のアカウントが「認証強度が必要」のポリシーに割り当たっていないことを指摘してくれています*

また、提案されたポリシーがまず「レポート専用モード」で作成される点は安全サイドに倒されていて好印象です。これにより、実際のユーザーに影響を与える前に、新しいポリシーが誰にどのような影響を及ぼすのか（サインインログで影響を受けるユーザーを確認できる）を安全に評価する時間が確保されます。この安心感は、本番環境への変更に慎重なエンタープライズ管理者にとって非常に重要です。

### レビューの観点・提案の幅は「現時点では」限定的

一方で、現状のエージェントができることは、まだ限定的です。現時点では、MFAや準拠デバイスといった基本的な保護が適用されていない24時間以内に作成したユーザーを検出したり、ポリシーの重複をレビューすることなどが基本です。つまり、「経営陣のスマホ利用時だけ条件付きアクセスの条件が違う設定になっているけど、なんでこうなっているんだっけ？こんな手段あるから見直したら？」といった、より高度で文脈に応じた分析はまだできません。

カスタム指示を書くことで、観点を補足することはできますが、カスタム指示で観点を出せるならば、自分でもその点でチェックできるということです。一方、我々がAIへの期待の大きな要素としては自分でも認識していなかった観点の提示という点があるので、その点では若干の物足りなさを感じます。「万能のAIコンサルタント」というよりは、「基本に忠実な新人の監査役」といったイメージが近いかもしれません。一方、最新のモデルの精度を考えると、もっとできるのでは？と率直に思ってしまうので、今後はレビューの観点が増えていくことを期待します。

![image](https://github.com/user-attachments/assets/bfff0792-e460-408b-bce1-4f9971b16f98)
**カスタム指示**

:::message
なので、全てのユーザーに一律で同じポリシーを使ってMFAもしっかりやっているような企業には現時点では刺さりにくいのかなと思います。しかしながら、AIは驚異的なスピードで発展しているので、継続的に進化をウォッチすることをお勧めします。最初微妙でも気が付いたら凄くなっていたりするので。
:::

### オンデマンド vs エージェント！継続的評価をシームレスに実施できるのが良い

ビジネスの状況もM365の機能も刻一刻と変化します。そういったものの積み重ねにIT部門としては対応していかなければならないため、定期的な監査などでセキュリティを担保することは到底不可能です。そういった中で、Agentが毎日毎日差分をレビューしてくれるのは大変価値があるなと率直に感じました。小さい会社であればポリシーがシンプル化していると思いますが、大きな会社になると複雑怪奇になることがあるので、人間のチェックをオンデマンドで毎日回すのはコスト的に到底難しいですが、そこはAIならではですね。願わくば、M365全体のポリシーを毎日レビューしてくれる日が来たら嬉しいものです。

## おわりに

この新機能は現状ではまだ見る観点が狭く発展途上ですが、その真価は将来性にあります。現在の最新モデルが適用されることを考えると、そのポテンシャルは計り知れません。ポリシー管理を属人化された手作業から、AIが支援する客観的で継続的なプロセスへと昇華させるための、これは重要な第一歩だと感じましたし、Security Copilot のトリガーが人の手を離れて、継続的に反復してくれるのは嬉しい傾向だと感じました。

個人的に「AIエージェント」を主語に進めると、ミスリードや「これじゃなかった感」が起きてしまうので好きではないのですが、「AIに渡す玉を大きくする」というイメージで色々なAgentと名の付くソリューションを試したり、作ってみたりしたいと思います。

![image](https://github.com/user-attachments/assets/f0166910-e9db-4dbe-9053-8d65eb690cee)
