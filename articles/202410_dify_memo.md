---
title: "Difyで気になったこと個人的なメモ"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [Dify, Security] 
published: true
---
Dify 周りで個人的に気になったことをメモしていきます。

## 免責事項
- 情報については公開日時点の情報です。
- 個人的なメモなので悪しからず。

## Difyの概要
- Difyは利用して大規模言語モデル（LLM）を活用したアプリケーションを構築、管理、最適化するためのソフトウェアです。^[[Dify](https://dify.ai/)]
- Difyはオープンソースプロジェクトとして提供されており、ユーザーは自分のインフラ上でプラットフォームをセルフホストすることができます。
- また、Dify Cloudというオプションも提供されており、クラウド上での利用が可能です。

## 会社について
### 運営会社
- Difyは、LangGenius, Inc.によって開発・運営されています。^[[Dify](https://dify.ai/)]
- この企業は2023年に設立され、米国デラウェア州に登記されています。^[[Dify](https://dify.ai/)]

### 創業者
- DifyのCEOはLuyu Zhang氏です。
- 彼は元 Tencent Cloud で働いた後、LangGenius, Inc.を創業しました。^[[Luyu Zhang](https://www.linkedin.com/in/luyu-zhang)]

### 資本関係
- Difyは Delian Capital からシードラウンドで資金を調達しています。^[[https://dify.ai/terms](https://www.crunchbase.com/organization/langgenius-inc/company_financials)]
- Delian Capitalは、2011年に設立された中国北京市に本社を置くベンチャーキャピタル会社です。主に技術主導型産業に特化しており、ハイエンド製造、最先端技術、ヘルスケアなどの分野に投資しています。^[[https://dify.ai/terms](http://www.bjdeliancap.com/en)] ^[[delian-capital](https://www.crunchbase.com/organization/delian-capital)]

## セキュリティ（クラウド版）
### 準拠法及び管轄裁判所 ^[[Dify Terms](https://dify.ai/terms)]
- Difyの米国デラウェア州の法律に準拠しています。
- 管轄裁判所はカリフォルニア州サンフランシスコにある裁判所としています。

### ホスト先
- アメリカのAWS上でホストされています。^[[Dify Terms](https://dify.ai/terms)]
- ただし、プライバシーポリシーを確認すると以下のように記載されており、中国を含む他の国にもデータが流通する可能性があります。^[[Dify Privacy Policies](https://docs.dify.ai/ja-jp/policies/agreement)]
> The information collected through our website and our products may be stored and processed in any country/region where LangGenius or its affiliated companies or service providers maintain facilities, including your region, the United States, Australia, Canada, China, and the European Economic Area (including the United Kingdom).
> （筆者意訳：当社のウェブサイトおよび製品を通じて収集された情報は、お客様の地域、米国、オーストラリア、カナダ、中国、欧州経済地域（英国を含む）など、LangGenius またはその関連会社またはサービス プロバイダーが施設を維持している国/地域で保存および処理される場合があります。）

### 認証
- Difyは、AICPAが定める SOC II を Type 1 の報告書を受領しています。(チェックしたい)^[[https://docs.dify.ai/ja-jp/policies/agreement](https://x.com/dify_ai/status/1845852984330334512)]
- ISO 27001 及び GDRP への準拠はまだです。^[https://docs.dify.ai/ja-jp/policies/agreement]
- その他の情報については [Trust Center](https://security.dify.ai/) などで確認できます。
