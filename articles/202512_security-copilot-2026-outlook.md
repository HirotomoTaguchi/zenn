---
title: "Security Copilot の現在価値と今後の展望"
emoji: "🛡" 
type: "idea" ## tech: 技術記事 / idea: アイデア記事
topics: [Microsoft Defender, Security, SIEM&XDR, Security Copilot] 
published: false
---

:::message
このブログは個人の感想（ポエム）です。なんの保証も致しかねます。
:::

アドベントカレンダーということで、今回はMicrosoft Security Copilotについて書いていきます。この1年間、実際に触れてみて感じた現在の価値と、2026年に向けた展望をまとめてみたいと思います。フワッとした話ですが、年末なので許してください。

## 3行まとめ

- Security Copilotは時給約600円で計算すればフル活用時の価値は高いが、リソースを常時確保する必要があるため、活用条件が整わないと割高になる
- E5ライセンスへの組み込み(1000ライセンスごとに400SCU)により、価格面のハードルが大幅に下がった
- 2026年はエンタープライズSOCを中心に、本格的な活用が加速する年になりそう

## Security Copilotとは？

Security Copilotは、Microsoft 365 CopilotなどのビジネスCopilotとは異なり、脅威インテリジェンス、業界のベストプラクティス等を組み込んだセキュリティ運用に特化したAIアシスタントです。Defender for EndpointやSentinelなどのセキュリティ製品と連携し、セキュリティの業務を支援します。2024年は日本でも一般提供が開始され、いよいよ本格的に使えるようになった年でした。^[[What-is-microsoft-security-copilot](hhttps://learn.microsoft.com/en-us/copilot/security/faq-security-copilot#what-is-microsoft-security-copilot)]

## Security Copilotの現在価値

2025年時点で、Security Copilot を使っていて最も価値を感じるのは、経験の浅いメンバーが「Defenderが勝手に対応してくれました」という状況から脱却するのを手助けしてくれる点だと筆者は感じています（個人の感想です）。これまで、Microsoft Defender for Endpoint(MDE)やMicrosoft Defender for Identity(MDI)が自動で検知・対処してくれるのはありがたい反面、経験の浅いメンバーにとって実際に何が起きたのか理解するには、それなりの知識と経験が必要でした。セキュリティ事故を起こせば膨大な被害が及ぶので「Defenderが勝手に対応してくれました」では無責任すぎます。

Security Copilotはこうした状況を少しだけ改善する実感を得ています。インシデントの概要を自然言語で要約し、関連するアラートやエンティティの関係性を整理してくれるため、「何が起きたのか」を理解するまでの時間を短縮する手助けをしてくれます。

![](https://github.com/user-attachments/assets/b72fad54-39f1-46e5-8fd0-5413e626b1bd)

もちろん、「AIがこう言っています」は「Defenderが勝手に対応してくれました」と同じぐらい無責任なことですが、ゼロから読み解くよりは時短できると思います。時給換算で約600円という価格設定は、フル活用できる環境であれば十分に投資対効果が見込める水準だと感じています。

## 現在の課題

とはいえ、Security Copilotの導入には大きな課題がありました。それは、SCU(Secure Compute Unit)という重量課金のリソースを常時有効にしておく必要がある点です。使っても使わなくても、リソースを確保している限り課金が発生します。この仕組みは、セキュリティインシデントが頻繁に発生し、常にSecurity Copilotを使い続けられる環境であればペイできる可能性があります。しかし、多くの組織では、セキュリティ運用の業務量にはムラがあります。

また、ユースケースもまだ少ないのが実情であり、Defender XDR シリーズや Purview などをガッツリ使い込んでいることが、コスト分をペイするために不可欠だなとも感じておりました。エージェントなどもありますが、使った分だけ課金される Azure OpenAI を使った方が価値が出やすいなと思います。

こうした利用パターンでは、リソースの稼働率が低くなり、結果としてコストパフォーマンスが悪化します。稟議書を書こうにも、「フル活用できる条件が整っているか」という問いに自信を持って答えられないケースが多いのではないでしょうか。ある程度の規模があり、専任のSOCチームが存在し、日々多数のアラートをトリアージしているような環境でなければ、導入の判断は難しかったというのが正直なところです。

## E5への組み込まれるようになったよ！

そんな中、大きな転換点が訪れました。Security CopilotがMicrosoft 365 E5ライセンスに組み込まれることになったのです。具体的には、1000ライセンスごとに400SCUが付与される形になります。これは価格面での最大のハードルを突破したいうか、ゲームチェンジですね。既にE5を導入している組織であれば、追加の予算確保なしにSecurity Copilotを試せるようになりました。E5という既存のライセンス体系の中に組み込まれたことで、ハードルは格段に下がったと感じています。

## 2026年の展望

2026年は、ビックなエンタープライズを中心に Security Copilot の活用が本格化する年になると予想しています。なんせ、追加料金なしで使えるのですから。特に期待されるのは、以下のような場面での活用です。

### 経験の浅いアナリストの強化

まず、先ほどの繰り返しとなりますが、経験の浅いアナリストへの補助が強化されます。セキュリティ人材の不足は深刻な問題ですが、Security Copilotがあれば、経験の浅いメンバでもベテランの知見を借りながら業務を進められます。インシデントの読み解き方、対処方針の立て方、エスカレーションの判断など、これまで先輩に聞きながら学んでいたことを、AIの支援を受けながら進められるようになります。

### L1アナリストのトリアージの巻き取り

また、L1アナリストが担当するトリアージ業務の自動化も進むかなと期待しています。AIは「知的単純作業の自動化」が得意だと言われますが、まさにL1レベルのアラートトリアージは「知的単純作業」の典型です。大量のアラートから明らかな誤検知を除外し、優先度をつけて上位レベルにエスカレーションするという業務は、AIが最も力を発揮できる領域だと考えています。

もちろん、生成AIを使わなくてもトリアージを自動化するという取り組みは「SOAR」という文脈で数多く行われてきました。しかしながら、Securi Copilot は、組織の規定や個別のケースへのFBを含めることができるので、組織固有のセキュリティ運用プロセスに最適化された使い方が広がっていくはずです。例えば、以下のようなトリアージエージェントが出てきており、今後も組み込み/オリジナル問わずトリアージに関するエージェントが進んでいくと思われます。

- フィッシングトリアージエージェント
- PurviewのDLPトリアージエージェント^[[Introducing Microsoft Purview Alert Triage Agents for Data Loss Prevention & Insider Risk Management](https://techcommunity.microsoft.com/blog/microsoftmechanicsblog/introducing-microsoft-purview-alert-triage-agents-for-data-loss-prevention--insi/4424401)]
- PurviewのDLPトリアージエージェント^[[Introducing Microsoft Purview Alert Triage Agents for Data Loss Prevention & Insider Risk Management](https://techcommunity.microsoft.com/blog/microsoftmechanicsblog/introducing-microsoft-purview-alert-triage-agents-for-data-loss-prevention--insi/4424401)]

## おわりに

2025年は多くのセキュリティインシデントが世間を騒がせました。完璧なセキュリティは存在しませんが、2026年はAIの力を借りることで、少しでも多くのインシデントを防げる未来に近づいていければと思います。
