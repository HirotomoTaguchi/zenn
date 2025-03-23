---
title: "Advanced Hunting"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [Intune, MAC] 
published: false
published_at: 2024-12-31 08:00
---

# Alerts and Behaviors

### AlertEvidence
`AlertEvidence` スキーマは、アラートをトリガーしたイベントに関する追加情報を提供します。 これには、アラートに関連するファイル名、プロセス名、レジストリキー、IPアドレス、URLなどのエンティティ情報が含まれます。

**ユースケース:**

- **セキュリティ調査:** 調査担当者は、AlertEvidenceを使用して、*特定の警告に関与するすべてのインジケーター*を掘り下げることができます。たとえば、警告IDまたはタイトルが与えられた場合、その警告の悪意のあるファイル、URL、または影響を受けたデバイスのリストを取得して、その範囲を理解することができます。これは、インシデントレスポンダーが警告によって何が影響を受けたかを確認するのに役立ちます。
  - *基本的なクエリ:* 特定の警告（AlertIdまたはTitle別）のエビデンスエンティティを取得します。これにより、さらなる分析のために、その警告に関与するすべてのファイル、IPなどがリスト表示されます。例：
    ```kql
    // 特定のタイトルを持つ警告のすべてのエビデンスエンティティを取得
    AlertEvidence
    | where Title == "Suspicious PowerShell Behavior"
    | project Timestamp, EntityType, EvidenceRole, FileName, SHA1, AccountName, DeviceName
    ```
  - *高度なクエリ:* ある警告のインジケーターが別の警告に現れるかどうかを特定します（関連するインシデントをリンクします）。たとえば、**複数の**異なる警告でエビデンスとなっているファイルハッシュを見つけます。これは、広範囲にわたる脅威を示している可能性があります。
    ```kql
    // 複数の警告に現れるファイルハッシュを見つける（潜在的な拡散）
    AlertEvidence
    | where EntityType == "File" and isnotempty(SHA1)
    | summarize AlertCount=dcount(AlertId), Alerts=make_set(Title) by SHA1, FileName
    | where AlertCount > 1
    | project FileName, SHA1, AlertCount, Alerts
    ```
    このクエリは、複数の警告をトリガーしたファイルを検索し、調査担当者が関連する警告を接続したり、既知の悪意のあるファイルがインシデント全体で再発しているかどうかを確認したりするのに役立ちます。

- **脅威ハンティング:** 脅威ハンターは、警告全体のパターンについてAlertEvidenceをクエリして、脅威をプロアクティブに特定できます。たとえば、特定の**MITRE ATT&CKテクニック**または既知のマルウェアファミリーに関連するすべての警告エビデンスを検索して、そのテクニックまたはマルウェアが検出されたことを示すことができます。別のハンティングアプローチは、特定のエンティティ（異常な外部IP範囲やドメインなど）を含む警告を見つけることです。
  - *基本的なクエリ:* 特定の脅威ファミリーまたはATT&CKテクニックに関与した警告を検索します。たとえば、エビデンスが**フィッシング**活動（MITREテクニックT1566）または既知のマルウェアファミリーを示しているすべての警告を見つけます。
    ```kql
    // フィッシング試行を示す警告エビデンスを検索（ATT&CK T1566）
    AlertEvidence
    | where AttackTechniques has "T1566"  // フィッシングテクニック
      or ThreatFamily == "Phishing"
    | project Timestamp, AlertId, Title, EvidenceRole, RemoteUrl, AccountUpn
    ```
    これは、フィッシングに関連する警告（およびそのエビデンス）を返します。
  - *高度なクエリ:* 警告における*共通のターゲットまたはソース*（複数の警告でエビデンスとして現れるIPアドレス（おそらくコマンドアンドコントロールサーバー））を特定します。たとえば、複数のデバイスで警告エビデンスのリモートIPであった**IPアドレス**を見つけます。
    ```kql
    // 複数のデバイスの警告に現れる疑わしいIPを見つける
    AlertEvidence
    | where isnotempty(RemoteIP)
    | summarize DevicesAffected=dcount(DeviceId), AlertCount=dcount(AlertId) by RemoteIP
    | where DevicesAffected > 1
    | sort by AlertCount desc
    ```
    これは、複数のマシンで警告をトリガーしたIPを表面化させます。これは、広範囲にわたる攻撃者のインフラストラクチャの可能性のある兆候です。

- **コンプライアンスチェック:** セキュリティ運用において、AlertEvidenceを使用して、脅威がポリシーに準拠して修復されていることを確認できます（例：SLA内で対応された重大度の高い警告、または悪意のある成果物が削除されたこと）。たとえば、特定の日付より古い重大度の高い警告エビデンス（潜在的な期限切れのインシデントを示す）を確認したり、警告によって特定された悪意のあるファイルが環境内に存在しないことを確認したりできます。
  - *基本的なクエリ:* 7日以上前のすべての**重大度の高い**警告（そのエビデンスエントリを介して）をリスト表示します。これは、予想される期間内に完全に解決されていない可能性のあるインシデントを示している可能性があります。
    ```kql
    // 7日以上前の重大度の高い警告（エビデンス経由）を特定
    AlertEvidence
    | where Severity == "High" and Timestamp < ago(7d)
    | summarize Alerts=dcount(AlertId) by Title, max(Timestamp)
    ```
    これは、インシデント対応SLAのコンプライアンス追跡のために、重大度の高い警告のタイトルと最後に確認された日時を示します。
  - *高度なクエリ:* 警告からの悪意のあるファイルが修復されたことを確認します。たとえば、最近のマルウェア警告からのファイルハッシュを取得し、これらのファイルが警告時刻**後**に任意のデバイスで実行されたかどうかを確認します（これは、脅威が持続しており、修復におけるコンプライアンスギャップがあることを意味します）。
    ```kql
    // マルウェア警告のファイルが警告後に再度実行されたかどうかを確認（修復チェック）
    let recentMalware = AlertEvidence
      | where EntityType == "File" and ThreatFamily != "" and Timestamp > ago(14d)
      | project AlertId, SHA1, AlertTime=Timestamp;
    recentMalware
    | join kind=inner (
        DeviceProcessEvents
        | project SHA1, ProcessCreationTime
      ) on SHA1
    | where ProcessCreationTime > AlertTime  // 警告発生後の実行
    | project SHA1, AlertId, AlertTime, ProcessCreationTime, DeviceName
    ```
    このクロス表クエリは、最近のマルウェア警告で特定され、その後その警告後にデバイスで実行されたファイル（SHA1ハッシュ別）を見つけます。セキュリティチームはこれを使用して、マルウェアファイルがポリシーで義務付けられているとおりに隔離または削除されたことを確認し、再発したものをフラグ付けできます。

### AlertInfo
**スキーマの説明:** `AlertInfo`テーブルには、Defender for Endpoint、Defender for Office 365、Defender for Cloud Apps、Defender for Identityからの警告を含む、Microsoft 365 Defenderの各セキュリティ警告のレコードが含まれています（[高度な検索スキーマのAlertInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table#:~:text=AlertInfo)）。各警告レコードには、警告の**タイトル**、**カテゴリ**（脅威または侵害活動の種類）、**重大度**（低、中、高）、**ServiceSource**（警告を生成した製品またはサービス）、およびマッピングされた**MITRE ATT&CKテクニック**（[高度な検索スキーマのAlertInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table#:~:text=Column%20name%20Data%20type%20Description,that%20provided%20the%20alert%20information)）（[高度な検索スキーマのAlertInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table#:~:text=,activity%20that%20triggered%20the%20alert)）などの高レベルの情報が含まれています。このテーブルは、**警告の表示とフィルタリング**に使用され、多くの場合、調査の出発点として、または脅威の状況を把握するために使用されます（たとえば、重大度またはカテゴリ別の警告の数）。

**ユースケース:**

- **セキュリティ調査:** アナリストはAlertInfoを使用して、特定の警告の詳細を取得したり、カテゴリまたは重大度別に類似の警告を見つけたりします。たとえば、インシデントを調査する際に、影響を受けたデバイスのすべての警告、または同じ時間枠内のすべての警告を取得して、全体像を把握できます。
  - *基本的なクエリ:* ID（またはタイトル）で特定の警告のすべての詳細を取得します。これにより、調査担当者はその警告のコンテキスト（重大度、カテゴリなど）を迅速に把握できます。
    ```kql
    // AlertIdで特定の警告を取得
    AlertInfo
    | where AlertId == "<ALERT-ID-123>"
    ```
    *(`<ALERT-ID-123>`を目的の実際のAlertIdに置き換えてください。)* これは、タイトル、カテゴリ、重大度などを含む完全な警告レコードを返します。これは、インシデントレポートの概要として役立ちます。
  - *高度なクエリ:* インシデント中に特定のデバイスまたはユーザーに関連するすべての警告を調査します。たとえば、デバイスが侵害された疑いがある場合、過去24時間以内にそのデバイス上のすべての警告をリスト表示します。
    ```kql
    // 過去1日以内の特定のデバイス上の警告（デバイス名別）
    AlertInfo
    | where DeviceName == "HR-WKSTN-001.contoso.com"
      and Timestamp > ago(1d)
    | project Timestamp, Title, Severity, Category, ServiceSource
    | sort by Timestamp asc
    ```
    このクエリは、過去1日間の*HR-WKSTN-001*上の警告のタイムラインをまとめたもので、調査担当者が悪意のある活動のシーケンスとその種類を理解するのに役立ちます。

- **脅威ハンティング:** AlertInfoテーブルをクエリして、検出されていない問題や広範囲にわたるキャンペーンを示す可能性のある警告のパターンやクラスターを見つけることができます。ハンターは、カテゴリ別またはATT&CKテクニック別の警告の傾向を見て、さらに深く掘り下げる場所を仮説立てることがよくあります。
  - *基本的なクエリ:* **複数の重大度の低い警告が全体としてより大きな問題を示している可能性**を探します。たとえば、「ログイン失敗」または「パスワードスプレー」の重大度の低い警告が複数急増した場合、注意が必要になる可能性があります。簡単なクエリで、カテゴリまたはタイトル別に警告をカウントできます。
    ```kql
    // 過去7日間のタイトル別の警告数（異常な警告の急増を特定）
    AlertInfo
    | where Timestamp > ago(7d)
    | summarize AlertCount = count() by Title, Severity
    | sort by AlertCount desc
    ```
    最も頻繁な警告を確認することで、継続的な問題（たとえば、ブルートフォース攻撃の可能性のある試みを多数示すパスワードスプレー警告など）が明らかになる可能性があります。
  - *高度なクエリ:* **カバレッジのギャップまたは新たな攻撃テクニック**をプロアクティブに特定します。たとえば、過去1か月間に警告が発生していないATT&CKテクニックをリスト表示します（潜在的な盲点を示している可能性があります）。
    ```kql
    // 過去30日間に警告で確認されなかったMITREテクニックを見つける
    let techniquesSeen = AlertInfo
      | where Timestamp > startofday(ago(30d))
      | mv-expand technique = split(AttackTechniques, ",")
      | summarize by technique;
    AttckTechniqueReferences  // すべてのテクニックの仮説的な参照
    | where TechniqueID !in (techniquesSeen.technique)
    ```
    *(注：これは、すべてのテクニックIDの参照リスト`AttckTechniqueReferences`があることを前提としています。)* 目的は、警告で検出されていないテクニックを明らかにし、カバレッジを検証したり、レッドチーム演習を通じてテストしたりする領域を示すことです。

- **コンプライアンスチェック:** セキュリティ運用に関して、コンプライアンスとは、警告がポリシーに従って処理されていること、または検出範囲が特定の基準を満たしていることを保証することを意味する可能性があります。AlertInfoを使用すると、すべての重大度の高い警告が一定期間内に解決されたかどうかを確認したり、データ漏洩警告などのカテゴリが発生していないことを確認したりできます（ポリシーコンプライアンス）。
  - *基本的なクエリ:* **X日以上前の重大度の高い警告で、まだアクティブなもの**を特定します。これは、インシデント対応SLAに違反している可能性があります。（AlertInfoは「解決済み」ステータスを直接保存しませんが、アナリストは、警告がまだリストにあり、古い場合は未解決であると想定することがよくあります。）例：
    ```kql
    // 14日以上前の重大度の高い警告（潜在的に期限切れ）
    AlertInfo
    | where Severity == "High" and Timestamp < ago(14d)
    | project AlertId, Title, Category, Timestamp
    ```
    セキュリティ管理者はこのようなリストを確認して、重大な警告が見落とされたり、許可された期間を超えてオープンになったりしていないことを確認できます。
  - *高度なクエリ:* **ポリシー違反の警告** - 発生していない（またはほとんど発生していない）ことを確認します。たとえば、組織が未承認のクラウドアプリの使用を禁止するポリシーを持っている場合、そのポリシーが破られたときに*Cloud App*カテゴリに警告が表示される可能性があります。一定期間にそのような警告が何回発生したかを確認できます。
    ```kql
    // 過去30日間のポリシー関連の警告数（例：データ漏洩またはDLP）
    AlertInfo
    | where Category in ("Data Loss Prevention", "DataLeak", "ShadowIT")
      and Timestamp > ago(30d)
    | summarize AlertsCount = count()
    ```
    この数がゼロより大きい（または閾値より大きい）場合、コンプライアンスの問題（たとえば、ユーザーが機密データをメールで送信したり、未承認のアプリを使用したりするなど）を示しています。セキュリティチームは、発生したものをトレーニングまたは制御を通じて対処すべきコンプライアンス違反として扱う可能性があります。AlertInfoのこの使用法は、警告の観点からセキュリティポリシーの遵守を監視するのに役立ちます。

### BehaviorEntities (プレビュー)
**スキーマの説明:** `BehaviorEntities`テーブル（プレビュー）には、Microsoft Defender for Cloud Apps（旧MCAS）によって検出された**動作**に関する情報が含まれています（[高度な検索スキーマのBehaviorEntitiesテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorentities-table#:~:text=The%20,)）。Defender XDRにおける*動作*は、1つ以上の生イベントから派生したより高レベルの抽象化であり、ユーザーまたはエンティティのアクションに関するコンテキスト上の洞察を提供します（[高度な検索スキーマのBehaviorEntitiesテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorentities-table#:~:text=Behaviors%20are%20a%20type%20of,)）。このテーブルには、**これらの動作に関与するエンティティ**がリスト表示されます。各動作について、関連するエンティティ（ユーザー、ファイル、デバイスなど）をその役割とともに列挙できます。主要なフィールドには、**BehaviorId**（動作の一意のID）、**ActionType**（検出された動作/アクティビティの種類）、**EntityType**および**EntityRole**（エンティティの種類と、それがアクターかターゲットか）が含まれます（[高度な検索スキーマのBehaviorEntitiesテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorentities-table#:~:text=,)）（[高度な検索スキーマのBehaviorEntitiesテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorentities-table#:~:text=,)）、さらにファイル名、IP、アカウント情報などのコンテキストが含まれます。基本的に、BehaviorEntitiesはAlertEvidenceと概念的に似ていますが、*Cloud Appの行動アラート*に関するものであり、クラウドアプリのアラートや異常に関与した人物/物を特定します。

**ユースケース:**

- **セキュリティ調査:** Defender for Cloud Appsのアラート（動作）がトリガーされた場合（たとえば、「不可能旅行」や「ユーザーによる大量ダウンロード」）、調査担当者はBehaviorEntitiesを使用して、*どのユーザー、ファイル、またはその他のオブジェクト*が関与しているかを確認できます。これにより、動作アラートの内容が明確になります。
  - *基本的なクエリ:* BehaviorIdで特定のCloud Appの動作アラートのエンティティを取得します。たとえば、「不可能旅行」アラートを調査する場合、その動作の一部であったユーザーとIPエンティティをリスト表示します。
    ```kql
    // 特定の動作アラートに関与するエンティティを取得
    BehaviorEntities
    | where BehaviorId == "<Behavior-ID>"
    ```
    これにより、そのアラートに関連するすべてのエンティティ（たとえば、ユーザーアカウント、IPエンティティとしての送信元と宛先の場所）が得られます。アナリストは、異常をトリガーしたユーザーと、関連するエンティティ（ファイルやデバイスなど）を迅速に特定できます。
  - *高度なクエリ:* より豊富なコンテキストを得るために、動作アラートをデバイスまたはID情報と関連付けます。たとえば、BehaviorEntitiesをIdentityInfoと結合して、関与したユーザーの部署または職務を取得します（影響または意図を評価するのに役立ちます）。
    ```kql
    // クラウドアプリの動作のユーザーエンティティをIDの詳細で強化
    BehaviorEntities
    | where BehaviorId == "<Behavior-ID>" and EntityType == "User"
    | join kind=leftouter IdentityInfo on $left.AccountObjectId == $right.AccountObjectId
    | project BehaviorId, ActionType, AccountDisplayName, Department, Country = AccountCountry
    ```
    たとえば、これは、財務部門のユーザーが海外から異常なクラウド活動を実行したことを示す可能性があります。これは、調査担当者にとって貴重なコンテキストです。

- **脅威ハンティング:** BehaviorEntitiesをクエリして、テナント全体のクラウド使用における疑わしいパターンを明らかにすることができます。正式なアラートをトリガーしていなくても、動作レコードは検索可能です（動作は良性のものもあれば、アラートの前兆となるものもあるため）。ハンターは、同じユーザーによる複数の動作や、エンティティの異常な組み合わせを探すことがあります。
  - *基本的なクエリ:* **同じユーザーに関与する複数の異なる動作**を見つけます。これは、そのユーザーアカウントが異常な動作をしていることを示している可能性があります。たとえば：
    ```kql
    // 過去7日間に複数の異なる動作アラートに関連付けられたユーザー
    BehaviorEntities
    | where Timestamp > ago(7d) and EntityType == "User"
    | summarize BehaviorCount=dcount(BehaviorId), Actions=make_set(ActionType) by AccountUpn
    | where BehaviorCount > 1
    ```
    これにより、複数の動作アラート（おそらく不可能旅行*と*大量ダウンロード）が発生したユーザーが特定されます。これは、そのアカウントが侵害されているかどうかを調査する必要があることを示唆しています。
  - *高度なクエリ:* **危険なファイル活動を示すクラウドアプリの動作**を探します。たとえば、*機密ファイル*（特定のタグが付いているか、特定の方法で名前が付けられている場合）が異常な方法でアクセスされた動作を見つけます。
    ```kql
    // クラウド経由での潜在的なデータ漏洩 - 例：1人のユーザーによる複数のファイルダウンロード
    BehaviorEntities
    | where EntityType == "File" and FileName has "Confidential"
    | join kind=inner (BehaviorEntities | where EntityType == "User") on BehaviorId
    | project Timestamp, BehaviorId, User=AccountUpn, FileName, ActionType
    ```
    ここでは、「Confidential」という名前のファイルに関与する動作をフィルタリングし、同じBehaviorIdに関与するユーザーとそれらをペアにします。これは、ユーザーが多くの機密ファイルをダウンロードした場合（ActionTypeはCloud Appイベントで*MassFileDownload*のようなものになる可能性があります）を明らかにする可能性があります。

- **コンプライアンスチェック:** クラウドアプリの監視において、コンプライアンスには、特定の活動（未承認の場所からの機密データへのアクセスやデータ所在地違反など）にフラグが立てられることを保証することが含まれる可能性があります。BehaviorEntitiesは、そのようなポリシー違反の動作が発生したかどうか、および誰が関与したかを確認するのに役立ち、内部コンプライアンス監査をサポートします。
  - *基本的なクエリ:* **機密性の高いSharePointコンテンツへのアクセス**動作が記録されたかどうかを確認します（ポリシー違反の可能性を示す）。たとえば、組織がファイルの大量削除を禁止するポリシーを持ち、Defender for Cloud Appsがそれを監視している場合：
    ```kql
    // 大量ファイル削除に関連する動作アラートを見つける（コンプライアンス）
    BehaviorEntities
    | where ActionType == "MassDeletionActivity"
    | summarize Count=count() by BehaviorId
    ```
    そのような動作が存在する場合、それはコンプライアンスの問題を示しています（誰かが大量のファイルを削除しており、データ保持ポリシーに違反している可能性があります）。
  - *高度なクエリ:* **クラウドアクセスポリシー**（不可能旅行など）が実施されていることを確認します。たとえば、MFAまたはその他の制御を回避したユーザーを検出します。1つのプロキシは、*重大度が低下した、または完全なアラートにならなかった動作*を見ることです。BehaviorEntitiesだけでは「ポリシー合格/不合格」の情報がないかもしれませんが、BehaviorInfo（動作のアラート情報を含む）と一緒に使用できます。たとえば、「ImpossibleTravel」タイプのすべての*動作アラートをリスト表示し、ユーザーが管理者であるかどうか（より大きなコンプライアンス上の懸念事項）を確認*します。
    ```kql
    // 不可能旅行の動作をリスト表示し、ユーザーが管理者である場合にフラグを立てる
    let adminUsers = IdentityInfo | where JobTitle contains "Admin" or Roles has "Global Administrator" | distinct AccountObjectId;
    BehaviorInfo
    | where Description startswith "Impossible travel"
    | join kind=inner (BehaviorEntities | where EntityType == "User") on BehaviorId
    | extend IsAdmin = iff(AccountObjectId in (adminUsers), "Yes", "No")
    | project Timestamp, AccountUpn, IsAdmin, Description
    ```
    これは、「不可能旅行」のインシデントと、関与したユーザーが管理者であるかどうかを特定します。コンプライアンス担当者は、特権アカウントが不可能と思われる場所からログインしたケース（ポリシー違反だけでなく、重大な問題である可能性があるため）を特にレビューする可能性があります。このクロス表クエリは、コンプライアンスに関連する異常（管理者が場所ポリシーに違反するなど）を強調表示するのに役立ちます。

### BehaviorInfo (プレビュー)
**スキーマの説明:** `BehaviorInfo`テーブル（プレビュー）には、Microsoft Defender for Cloud Appsからの**動作ベースのアラート**に関する情報が含まれています（[高度な検索スキーマのBehaviorInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorinfo-table#:~:text=The%20,)）。BehaviorInfoの各エントリは、基本的に*クラウドアプリの動作に関するアラートレコード*であり、AlertInfoが従来のアラートに関するものであるのと同様です。これには、動作の**説明**、**カテゴリ**（脅威の種類またはポリシー名）、関連する**MITREテクニック**、および動作の時間範囲（StartTime/EndTime）などの詳細が含まれます（[高度な検索スキーマのBehaviorInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorinfo-table#:~:text=,)）（[高度な検索スキーマのBehaviorInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorinfo-table#:~:text=,)）。動作はクラウドサービスにおける潜在的に疑わしい活動のコンテキストを提供するため、このテーブルは*アラートの内容とその範囲*（期間、テクニックなど）を理解するのに役立ちます。つまり、BehaviorInfoはAlertInfoのクラウドアプリ版であり、各動作アラートを要約します。

**ユースケース:**

- **セキュリティ調査:** クラウドアプリセキュリティのアラート（たとえば、「複数ファイルの削除」や「不可能旅行」）が発生した場合、アナリストはBehaviorInfoを見て、そのアラートの詳細（何が起こったか、いつ開始/終了したか、どのテクニックまたはカテゴリに該当するか）を取得できます。これは、アラートの重大度と影響を迅速にトリアージするのに役立ちます。
  - *基本的なクエリ:* IDまたは説明で特定の動作アラートの詳細を取得します。たとえば、大量ダウンロードに関するアラートを調査する場合、そのアラートの情報を検索します。
    ```kql
    // IDでクラウドアプリの動作アラートを取得
    BehaviorInfo
    | where BehaviorId == "<Behavior-ID>"
    ```
    これにより、説明（例：*「SharePointからのファイルの大量ダウンロード」*）、重大度（利用可能な場合）、カテゴリなどのフィールドが返され、アラートの概要が示されます。
  - *高度なクエリ:* 一定期間内に特定の**ユーザーまたはアプリ**に関連するすべてのクラウドアプリの動作アラートをリスト表示します。たとえば、特定のユーザーが調査対象である場合、過去30日間のそのユーザーのクラウドアプリのアラートをリスト表示して、パターンがあるかどうかを確認します。
    ```kql
    // 過去30日間の特定のユーザーのクラウドアプリのアラート
    BehaviorInfo
    | where Timestamp > ago(30d) and AccountUpn == "alice@contoso.com"
    | project Timestamp, Description, Categories, AttackTechniques
    | order by Timestamp desc
    ```
    これにより、アリスに関連する動作アラートのタイムライン（たとえば、疑わしいOAuthアプリの使用、不可能旅行など）が提供され、調査担当者はアリスのアカウントが侵害されているか、ポリシーに違反しているかを把握するのに役立ちます。

- **脅威ハンティング:** 脅威ハンターはBehaviorInfoを使用して、エスカレーションされていない可能性のある異常を見つけたり、クラウドの動作を他のインシデントと関連付けたりできます。動作は、異常なログインパターンやデータアクセスなどの兆候を示す可能性があるため、ハンターは環境全体で特定の説明やカテゴリを検索することがあります。
  - *基本的なクエリ:* **同じユーザーに関与する同じタイプの複数の動作アラート**を探します。これは、より広範な問題を示している可能性があります。たとえば、複数のユーザーが「不可能旅行」アラートをトリガーした場合、それはアカウント侵害の試みのキャンペーンを示唆している可能性があります。
    ```kql
    // 過去7日間の説明別のクラウドアプリの動作アラート数
    BehaviorInfo
    | where Timestamp > ago(7d)
    | summarize AlertCount = count() by Description
    | sort by AlertCount desc
    ```
    「不可能旅行」または「OAuth同意の付与」の動作が頻繁に表示される場合、ハンターはさらに調査する可能性があります。これは、継続的な攻撃パターン（複数のユーザーがターゲットにされているなど）である可能性があるためです。
  - *高度なクエリ:* **長期にわたるまたは繰り返される動作**を特定します。これは、ステルス性の高い悪意のある活動を示している可能性があります。たとえば、StartTimeとEndTimeの間に長い期間がある動作アラートを見つけます（これは、長期にわたるデータアクセスを意味する可能性があります）。
    ```kql
    // 1時間以上の期間を持つ動作アラートを見つける
    BehaviorInfo
    | where datetime_diff("minute", EndTime, StartTime) > 60
    | project Description, StartTime, EndTime, AccountUpn
    ```
    これにより、OAuthアプリが通常よりも長い時間接続またはセッションを維持している（おそらくデータを吸い上げている）などの異常を捉えることができます。たとえ即座にブロックされなくてもです。

- **コンプライアンスチェック:** コンプライアンスの観点から見ると、クラウドアプリの動作は多くの場合、ポリシー（データ漏洩防止、異常な管理アクションなど）に関連しています。BehaviorInfoを使用すると、そのようなポリシー違反の動作が発生したかどうか、および誰が関与したかを確認し、内部コンプライアンス監査をサポートできます。
  - *基本的なクエリ:* **機密性の高いSharePointコンテンツへのアクセス**動作が記録されたかどうかを確認します（ポリシー違反の可能性を示す）。たとえば、組織がファイルの大量削除を禁止するポリシーを持ち、Defender for Cloud Appsがそれを監視している場合：
    ```kql
    // 大量ファイル削除に関連する動作アラートを見つける（コンプライアンス）
    BehaviorEntities
    | where ActionType == "MassDeletionActivity"
    | summarize Count=count() by BehaviorId
    ```
    そのような動作が存在する場合、それはコンプライアンスの問題を示しています（誰かが大量のファイルを削除しており、データ保持ポリシーに違反している可能性があります）。
  - *高度なクエリ:* **クラウドアクセスポリシー**（不可能旅行など）が実施されていることを確認します。たとえば、MFAまたはその他の制御を回避したユーザーを検出します。1つのプロキシは、*重大度が低下した、または完全なアラートにならなかった動作*を見ることです。BehaviorEntitiesだけでは「ポリシー合格/不合格」の情報がないかもしれませんが、BehaviorInfo（動作のアラート情報を含む）と一緒に使用できます。たとえば、「ImpossibleTravel」タイプのすべての*動作アラートをリスト表示し、ユーザーが管理者であるかどうか（より大きなコンプライアンス上の懸念事項）を確認*します。
    ```kql
    // 不可能旅行の動作をリスト表示し、ユーザーが管理者である場合にフラグを立てる
    let adminUsers = IdentityInfo | where JobTitle contains "Admin" or Roles has "Global Administrator" | distinct AccountObjectId;
    BehaviorInfo
    | where Description startswith "Impossible travel"
    | join kind=inner (BehaviorEntities | where EntityType == "User") on BehaviorId
    | extend IsAdmin = iff(AccountObjectId in (adminUsers), "Yes", "No")
    | project Timestamp, AccountUpn, IsAdmin, Description
    ```
    これは、「不可能旅行」のインシデントと、関与したユーザーが管理者であるかどうかを特定します。コンプライアンス担当者は、特権アカウントが不可能と思われる場所からログインしたケース（ポリシー違反だけでなく、重大な問題である可能性があるため）を特にレビューする可能性があります。このクロス表クエリは、コンプライアンスに関連する異常（管理者が場所ポリシーに違反するなど）を強調表示するのに役立ちます。

---

# アプリとID

### AADSignInEventsBeta
**スキーマの説明:** `AADSignInEventsBeta`は、Microsoft Entra ID（Azure AD）のインタラクティブおよび非インタラクティブなサインインからの生のサインインイベントデータを提供する**ベータ**テーブルです（[高度な検索スキーマのAADSignInEventsBetaテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table#:~:text=The%20,)）。データが完全に`IdentityLogonEvents`にマージされるまで、DefenderでAzure ADサインインログを検索できるように導入されました（[高度な検索スキーマのAADSignInEventsBetaテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table#:~:text=The%20,)）。このテーブルには、使用された**アプリケーション**、**LogonType**（インタラクティブ、RDPなど）、サインインの**CorrelationId/SessionId**、ユーザーの詳細（DisplayName、UPN、ObjectId）、および失敗したログインの**ErrorCode**などのステータス/エラー情報など、Azure ADサインインログにあるフィールドが含まれています（[高度な検索スキーマのAADSignInEventsBetaテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table#:~:text=,)）（[高度な検索スキーマのAADSignInEventsBetaテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table#:~:text=the%20duration%20of%20the%20visit,external)）。基本的に、ハンティングのためにクラウド認証イベント（Azure ADに接続されたアプリやサービスへのユーザーログイン）を表面化させます。

**ユースケース:**

- **セキュリティ調査:** 調査担当者は、アカウントの侵害または疑わしいログイン試行を調査する際に、このテーブルをクエリしてユーザーのAzure ADログインアクティビティに関する詳細を収集できます。たとえば、ユーザーのアカウントが侵害された疑いがある場合、最近のサインインイベント（時間、場所、デバイス情報、成功/失敗）を確認することが重要です。
  - *基本的なクエリ:* 特定のユーザーの最新のAzure ADサインインイベントをいくつか取得して、異常なログイン試行（たとえば、奇妙な時間やMFAの失敗を示すエラーコード）があったかどうかを確認します。
    ```kql
    // 特定のユーザーの最新のサインインイベント5件
    AADSignInEventsBeta
    | where AccountUpn == "jdoe@contoso.com"
    | sort by Timestamp desc
    | take 5
    | project Timestamp, Application, LogonType, IsExternalUser, IsGuestUser, ErrorCode
    ```
    これは、ジョン・ドウがいつ、どのようにログインしたか、外部/ゲストとしてフラグが立てられたかどうか、およびエラーコード（サインインの失敗など）を示しています。調査担当者は、ジョンが連続してログインに失敗したり、異常なアプリからログインしたりした場合に気づくことができます。
  - *高度なクエリ:* 疑わしいサインインをデバイス情報と関連付けて調査します。たとえば、異常なサインインが見られた場合、Azure ADデバイスIDを介して関連付けられたデバイス（ある場合）を知りたい場合があります。`DeviceInfo`とAadDeviceIdで結合できます。
    ```kql
    // デバイス情報でサインインイベントを強化（デバイスがAzure ADに参加している場合）
    AADSignInEventsBeta
    | where AccountUpn == "jdoe@contoso.com" and Timestamp between (datetime(2025-03-01) .. datetime(2025-03-05))
    | join kind=leftouter (DeviceInfo | project AadDeviceId, DeviceName, OSPlatform) on $left.DeviceId == $right.AadDeviceId
    | project Timestamp, AccountDisplayName, Application, DeviceName, OSPlatform, IPAddress, IsExternalUser, ErrorCode
    ```
    これにより、ジョンがこれらのログイン中にどのデバイスを使用したか、およびそのデバイスが企業のものであるかなどのコンテキストが提供されます。不明なデバイスまたはIPからのログインがあった場合、調査で目立ちます。

- **脅威ハンティング:** ハンターはAADSignInEventsBetaを使用して、悪意のあるログイン試行のパターンを見つけることができます。たとえば、ブルートフォース攻撃やトークンリプレイ攻撃は、多数の失敗したログインまたは異常なユーザーエージェントとして現れる可能性があります。このテーブルはインタラクティブおよび非インタラクティブなサインインをログに記録するため、ログインの動作における異常を検索できます。
  - *基本的なクエリ:* パスワードスプレーまたはブルートフォースを示す可能性のある**失敗したサインインパターン**を探します。たとえば、同じIPまたは同じUserAgentからの多数のアカウント全体での複数の失敗したサインイン（ErrorCode != 0は失敗を示します）を探します。
    ```kql
    // 潜在的なパスワードスプレー：同じIPからの多数のログイン失敗
    AADSignInEventsBeta
    | where ErrorCode != 0 and Timestamp > ago(1d)
    | summarize Attempts=count(), Users=make_set(AccountUpn) by IPAddress, UserAgent
    | where Attempts > 10
    ```
    これにより、1日に多くの失敗があったIPが表面化します。*Users*セットに多数の異なるアカウントが含まれている場合、それは典型的なパスワードスプレー攻撃パターンです。
  - *高度なクエリ:* 疑わしいサインインの特性（たとえば、攻撃者ツールである可能性のあるまれな**UserAgent**）を特定します。たとえば、悪意のある使用で知られる特定の異常なユーザーエージェント文字列（一部のブルートフォースツールで使用される`"fasthttp"`ライブラリなど（[Entra IDでの'fasthttp'ブルートフォース攻撃の検出 - Rogier Dijkman](https://rogierdijkman.medium.com/detecting-fasthttp-bruteforce-attacks-on-entra-users-42ceb13bf856#:~:text=Detecting%20%27fasthttp%27%20bruteforce%20attacks%20on,indicates%20a%20failed%20login)））でフィルタリングします。
    ```kql
    // 既知の悪意のあるユーザーエージェントを使用したサインインを検索
    AADSignInEventsBeta
    | where UserAgent contains "fasthttp" or UserAgent contains "python-requests"
    | project Timestamp, AccountUpn, IPAddress, Application, UserAgent, ErrorCode
    ```
    このようなエントリ（特に多くの失敗を伴う場合）が表示された場合、カスタムクライアントを使用した自動攻撃またはトークン盗難の試みを示している可能性があります。ハンターは、これらの試みのいずれかが最終的に成功したかどうか（多くの失敗の後のErrorCode == 0）を確認することで、これを拡張することもできます。

- **コンプライアンスチェック:** IDのコンテキストでは、コンプライアンスには、承認されたログイン方法のみが使用されていること、またはすべての外部ログインが適切に制限されていることを保証することが含まれる場合があります。AADSignInEventsBetaは、そのようなポリシーの検証に役立ちます。たとえば、ポリシーで禁止されている場合、レガシー認証が使用されていないことを確認したり、ゲスト/外部ユーザーアクセスが監視されていることを確認したりできます。
  - *基本的なクエリ:* **レガシー認証**の試行（たとえば、LogonTypeまたはApplicationが示す場合、最新の認証/MFAをサポートしない古いプロトコルを使用）を特定します。組織のポリシーでレガシープロトコルが禁止されていると仮定すると、疑わしいLogonType値を持つサインインを検索できます。
    ```kql
    // 非インタラクティブなレガシーログイン（例：基本認証を使用）を検出
    AADSignInEventsBeta
    | where LogonType == "Legacy" or Application startswith "Office365/ActiveSync"
    | summarize Count = count() by Application, AccountUpn, LogonType
    ```
    これが結果を返す場合、誰かがレガシー認証（ActiveSync基本認証など）を使用または試行しており、ポリシーに違反しています。これにより、条件付きアクセスを強制したり、それらのアカウントのさらなる調査を促したりする可能性があります。
  - *高度なクエリ:* すべての**外部ユーザーログイン**がポリシーに従っていることを確認します。たとえば、外部ユーザー（ゲスト）は特定のアプリケーションのみにアクセスできる必要がある場合、それを検証できます。`IsExternalUser`または`IsGuestUser`フラグを使用して、外部ユーザーがどのアプリにログインしているかをリスト表示します。
    ```kql
    // 外部ユーザーのサインイン概要（過去30日間）
    AADSignInEventsBeta
    | where Timestamp > ago(30d) and IsExternalUser == 1
    | summarize count() by Application, IsGuestUser
    ```
    これにより、どのアプリケーションが外部IDによってアクセスされているか、およびそれらがゲストアカウントであったかどうかの内訳が示されます。ポリシーで内部従業員のみが使用すべきアプリに外部ユーザーがログインしている場合、それは非準拠です。たとえば、外部ユーザーが内部人事システムにログインした場合、フラグが立てられます。セキュリティチームまたはIAMチームは、それに応じてアクセスポリシーを調整できます。

### AADSpnSignInEventsBeta
**スキーマの説明:** `AADSpnSignInEventsBeta`は、Microsoft Entra IDにおける**サービスプリンシパルおよびマネージドIDのサインインイベント**のベータ版テーブルです（[defender-docs/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md at public · MicrosoftDocs/defender-docs · GitHub](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md#:~:text=The%20,)）。AADSignInEventsBetaがユーザーのサインインをログに記録するのに対し、このテーブルはアプリケーション（サービスプリンシパル）またはマネージドID（多くの場合、自動化およびサービスに使用）によるサインインをログに記録します。これには、**ServicePrincipalName/Id**、マネージドIDであったかどうかを示す`IsManagedIdentity`フラグ、アクセスされた**リソース**（ResourceId、ResourceDisplayName）、およびCorrelationId、IP、エラーコードなどの共通フィールドが含まれます（[defender-docs/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md at public · MicrosoftDocs/defender-docs · GitHub](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md#:~:text=Column%20name%20Data%20type%20Description,in%20event)）（[defender-docs/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md at public · MicrosoftDocs/defender-docs · GitHub](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md#:~:text=,)）。これは、アプリのログインを検索し、アプリの資格情報の潜在的な悪用や悪意のあるOAuthアクティビティを検出するのに役立ちます。（注：最終的にこれらのイベントもIdentityLogonEventsに移行します（[defender-docs/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md at public · MicrosoftDocs/defender-docs · GitHub](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table.md#:~:text=The%20,)）。）

**ユースケース:**

- **セキュリティ調査:** 悪意のあるアプリまたは侵害されたサービスプリンシパルトークンが使用された疑いがある場合、調査担当者はこのテーブルを参照します。たとえば、OAuthアプリケーションに不当な権限が付与された場合、その使用状況がここに表示されます。調査担当者は、ServicePrincipalIdまたはResourceでクエリを実行して、アプリが何をしたかを確認する場合があります。
  - *基本的なクエリ:* 特定の**アプリケーション**（サービスプリンシパル）の最近のサインインイベントを取得します。SPN IDが`abcd-1234`のアプリが疑わしい場合、そのログインをリスト表示できます。
    ```kql
    // 特定のサービスプリンシパルのサインインイベント
    AADSpnSignInEventsBeta
    | where ServicePrincipalId == "abcd-1234-efgh-5678"
    | sort by Timestamp desc
    | project Timestamp, ServicePrincipalName, ResourceDisplayName, IPAddress, ErrorCode
    ```
    これは、そのアプリ/サービスがいつ、どのリソースにログインしたか、そして成功したかどうか（ErrorCode 0は成功を意味します）を示しています。調査担当者は、アプリが異常な時間に、または異常なIPからリソースにアクセスした場合、それが悪用の可能性を示していることに気づくかもしれません。
  - *高度なクエリ:* 試みられた悪用を示唆する可能性のある**失敗したアプリのログイン**を調査します。たとえば、マネージドIDの失敗したサインイン試行（おそらく誰かがマネージドIDトークンを不適切に使用しようとした）をリスト表示します。
    ```kql
    // マネージドIDによる失敗したサインイン
    AADSpnSignInEventsBeta
    | where IsManagedIdentity == true and ErrorCode != 0
    | project Timestamp, ServicePrincipalName, ErrorCode, IPAddress, ResourceDisplayName
    ```
    マネージドIDに繰り返し失敗した試行があった場合、それは構成ミスまたはそのIDを悪用しようとする悪意のある試行を示している可能性があります。調査担当者は、それらの失敗がなぜ起こったのか（おそらく誰かがそのIDを意図されたコンテキスト外で使用しようとした）を確認します。

- **脅威ハンティング:** ハンターはこのテーブルをクエリして、アプリケーション間の疑わしい動作を見つけることができます。たとえば、侵害されたAzure ADアプリを攻撃者が不正にデータにアクセスするために使用する可能性があります。通常アクセスしないリソースへのアプリのアクセスや、異常な場所からのアクセスなどのパターンは、KQLを通じて明らかにできます。
  - *基本的なクエリ:* 最近ログインした、またはめったに見られない**新しいサービスプリンシパル**を探します。これは、攻撃者が登録したアプリを示している可能性があります。たとえば、過去1か月間に現れなかったアプリの過去1週間のサービスプリンシパルのサインインを見つけます。
    ```kql
    // 今週アクティブだが先月はアクティブでなかったサービスプリンシパル（可能性のある新しいアプリ）
    let lastMonthSPNs = AADSpnSignInEventsBeta
        | where Timestamp between (ago(37d) .. ago(7d))
        | distinct ServicePrincipalId;
    AADSpnSignInEventsBeta
    | where Timestamp > ago(7d) and ServicePrincipalId !in (lastMonthSPNs)
    | summarize NewLogins=count() by ServicePrincipalName, ServicePrincipalId
    ```
    これは、最近になってサインインアクティビティを示し始めたサービスプリンシパルを見つけます。ハンターはこれらを確認します。特に、一般的な名前または不明なアプリに対応するものがあれば、それらは不正である可能性があります。
  - *高度なクエリ:* **広範な同意またはマルチテナントアプリの悪用**を探します。たとえば、悪意のあるマルチテナントアプリがテナントでアクセスを許可されている場合、異常な海外IPまたは奇妙なリソースからのサインインが表示される可能性があります。複雑なクエリは、ログインIPが短時間で非常に異なる地域にまたがるサービスプリンシパルにフラグを立てる可能性があります（トークンの不正使用を意味します）。簡潔にするために、より簡単なアプローチ：組織が通常運用していない国のIPからのアプリのサインインを特定します。
    ```kql
    // 通常の国（たとえば、会社が事業を行っている米国またはEUではない）からのアプリのサインイン
    AADSpnSignInEventsBeta
    | extend Country = extractcountry(IPAddress)  // IPを国にマッピングする関数または方法を想定
    | where Country notin ("US","UK","DE","JP","CA")  // 通常の国以外
    | summarize Events=count() by ServicePrincipalName, Country
    ```
    内部アプリが、たとえば、ロシアや北朝鮮（あなたのビジネスがそこに存在しない場合）からのログインを示している場合、それはそのアプリのキーの盗難または悪意のある使用の可能性を示す危険信号です。

- **コンプライアンスチェック:** ここでのコンプライアンスは、アプリケーションが予期された方法で認証し、承認されたリソースのみにアクセスすることを保証することに関連する可能性があります。また、承認されていないサードパーティ製アプリが使用されていないことを確認することも意味する可能性があります。AADSpnSignInEventsBetaを使用して、どのアプリが何にアクセスしているかを監査できます。
  - *基本的なクエリ:* **アプリの使用状況の監査:** 過去1か月にサインインしたすべての異なるアプリケーション（サービスプリンシパル）をリスト表示して、それらが既知/承認済みであることを確認します。
    ```kql
    // 過去30日間にサインインアクティビティがあったサービスプリンシパルのリスト
    AADSpnSignInEventsBeta
    | where Timestamp > ago(30d)
    | summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by ServicePrincipalId, ServicePrincipalName, IsManagedIdentity
    ```
    セキュリティ/ITチームは、このリストを予想されるアプリのインベントリと照らし合わせて確認できます。予期しないサービスプリンシパル（特にマネージドIDではなく、見慣れないサードパーティ製アプリでもない場合）は、シャドーITまたは不正アクセスを示している可能性があり、これはコンプライアンスの問題です（変更管理または承認プロセスに違反しています）。
  - *高度なクエリ:* セキュリティコンプライアンスに沿って、アプリが**推奨されない認証フロー**を使用していないことを確認します（たとえば、すべてのアプリはクライアントシークレットではなく証明書ベースの認証を使用する必要がありますなど）。このテーブルは認証方法を直接示さないかもしれませんが、特定のパターンから推測できるかもしれません。別のコンプライアンスの観点：シークレットを持つサービスプリンシパルの代わりに、期待される場所で*マネージドID*が使用されていることを確認します。たとえば、マネージドIDを使用すべきAzureリソースへの通常のサービスプリンシパルによるサインインをリスト表示します。
    ```kql
    // マネージドでないサービスプリンシパルによるAzureリソースエンドポイントへのサインイン（シークレットベースの認証を示唆）
    AADSpnSignInEventsBeta
    | where IsManagedIdentity == false and ResourceDisplayName contains "Azure"
    | summarize count() by ServicePrincipalName, ResourceDisplayName
    ```
    ポリシーでAzureリソースにマネージドIDを使用するように定められている場合、ここでヒットしたものは、クライアント資格情報を使用しているアプリ（コンプライアンスの観点からは好ましくありません）を示しています。これは、クラウドセキュリティのベストプラクティスに沿った改善を促す可能性があります。

### CloudAppEvents
**スキーマの説明:** `CloudAppEvents`テーブルには、**クラウドアプリケーションおよびサービスにおけるイベント**に関する情報が含まれています。具体的には、Office 365およびDefender for Cloud Appsと統合されたその他のアプリにおけるユーザーアカウントとオブジェクトに関連するアクティビティです（[高度な検索スキーマのCloudAppEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table#:~:text=The%20,)）。これらのイベントには、SharePointからのファイルのダウンロード、SaaSアプリへのユーザーサインイン、Teamsでのアクセス許可の変更などが含まれます。フィールドには、**アクションの詳細**（ActionType、ActivityType）、**アプリケーション**（ApplicationおよびApplicationId（アプリ用）、例：SharePoint、Exchange）、**ユーザー/アカウント情報**（AccountDisplayName、AccountObjectId/UPN、およびユーザーが管理者であるか外部ユーザーであるか）、デバイスの種類、IPアドレス（地理情報付き）（City、CountryCode、IPAddressなど）、および影響を受けたオブジェクト（ActivityObjectsにはファイル名やアイテムがリスト表示される場合があります）などのコンテキストが含まれます（[高度な検索スキーマのCloudAppEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table#:~:text=Column%20name%20Data%20type%20Description,order%20by%20ApplicationId%2CAppInstanceId)）（[高度な検索スキーマのCloudAppEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table#:~:text=and%20surname%20of%20the%20user,to%20the%20device%20during%20communication)）。つまり、これはクラウドアプリ全体のユーザーアクティビティの統一ログであり、クラウドリソースアクセスに関するセキュリティ監視とコンプライアンス監査の両方に非常に役立ちます。

**ユースケース:**

- **セキュリティ調査:** ユーザーがクラウドサービスを不正に使用している疑いがある場合、または何らかのクラウドアクティビティによってアラートがトリガーされた場合、CloudAppEventsを使用すると、調査担当者は生イベントを確認できます。たとえば、潜在的なデータ窃盗インシデントでは、調査担当者はユーザーのファイルのダウンロードまたは共有イベントを確認します。
  - *基本的なクエリ:* 異常な動作を調査するために、特定のユーザーのOffice 365アプリ（SharePoint、OneDriveなど）全体の最近のアクティビティを取得します。例：
    ```kql
    // 特定のユーザーの最新のクラウドアプリイベント10件
    CloudAppEvents
    | where AccountUpn == "bob@contoso.com"
    | sort by Timestamp desc
    | take 10
    | project Timestamp, Application, ActionType, ActivityType, ActivityObjects, IPAddress, CountryCode
    ```
    これにより、調査担当者はすぐに概要を把握できます。ボブのアクション（ログイン、ファイルの表示、何かのダウンロードなど）、どのアプリ、どのIP/場所。ボブが異常な場所から多くのファイルをダウンロードした場合、アラートが直接フラグを立てなくても、ここに表示されます。
  - *高度なクエリ:* 特定のインシデント（たとえば、SharePointからの**大量ダウンロード**の報告）を調査します。特定のサイトまたはファイル名パターンとユーザーでCloudAppEventsをフィルタリングできます。たとえば、アラートで「ユーザーXがSharePointサイトYから100個のファイルをダウンロードしました」と表示された場合、次のように確認します。
    ```kql
    // 特定のSharePointサイトからユーザーによるファイルダウンロードイベントをフィルタリング
    CloudAppEvents
    | where Application == "SharePoint" and ActionType == "FileDownloaded"
      and AccountUpn == "userX@contoso.com"
      and ActivityObjects has "Site Y Name"
    | project Timestamp, AccountDisplayName, ActivityObjects, FileSize, IPAddress, IsAdminOperation
    ```
    これにより、ダウンロードされたファイル、そのサイズ、およびアクションが管理者権限で行われたかどうかの証拠が提供されます。調査担当者はこれを使用して、インシデントでアクセスされたデータの範囲を確認できます。

- **脅威ハンティング:** CloudAppEventsは、異常なクラウド使用状況をハンティングするための豊富なソースです。ハンターは、以前には実行されなかった管理者権限のような操作を単一のアカウントが実行するなどの異常なアクションの組み合わせ、またはOneDriveでのランサムウェア活動を示す可能性のある複数のファイル削除イベントなどを検索することがあります。
  - *基本的なクエリ:* **クラウド使用における不可能旅行**（サインインとは異なる）を検索します。たとえば、同じユーザーIDが短期間に地理的に大きく離れた場所からのイベントを持っている場合を見つけます。
    ```kql
    // 同じ日に2つの国でイベントが発生したユーザーを見つける簡単なアプローチ
    CloudAppEvents
    | summarize Countries = makeset(CountryCode) by AccountUpn, Date = bin(Timestamp, 1d)
    | where array_length(Countries) > 1
    ```
    ユーザーの`Countries`セットに、たとえば、同じ日に{"US","CN"}が含まれている場合、それは疑わしく、不可能旅行に似ています（ユーザーのクラウドアクティビティが同じ日に異なる国から発生しています）。ハンターはその後、これらのイベントをより深く掘り下げます。
  - *高度なクエリ:* 潜在的な**大量データ漏洩**またはデータ破壊を探します。たとえば、短期間に異常に多数のファイルを削除またはダウンロードしたユーザーを特定します（閾値が満たされていない場合、組み込みのアラートをトリガーしない可能性があります）。
    ```kql
    // 過去1時間に50件以上のファイル削除イベントが発生したユーザー（大量削除の可能性）
    CloudAppEvents
    | where ActionType == "FileDeleted" and Timestamp > ago(1h)
    | summarize Deletions=count() by AccountUpn
    | where Deletions > 50
    ```
    同様に、FileDownloaded > Xを確認することもできます。このようなクエリは、Defenderがまだアラートを上げていなくても、内部者が徐々にデータを漏洩させたり、侵害されたアカウントがファイルを大量に削除したり（ランサムウェアまたは妨害工作）するのを捉える可能性があります。ハンターはその後、これらのアカウントをすぐに調査できます。

- **コンプライアンスチェック:** CloudAppEventsを使用して、ITおよびデータ使用ポリシーの遵守状況を確認できます。たとえば、許可された個人のみが特定の機密ファイルにアクセスしたこと、またはO365での管理アクション（メールボックスのエクスポートなど）が追跡され、適切な担当者によって実行されたことを確認します。また、監査（たとえば、誰がSharePointサイトにアクセスしたか）にも役立ちます。
  - *基本的なクエリ:* **データアクセスコンプライアンス:** 許可されたグループ外のユーザーによる機密ファイルまたはサイトへのアクセスをリスト表示します。機密ファイルにタグを付けたり、命名規則（たとえば、「HR-confidential」を含むファイル）を知っている場合は、HR以外の人がそれらにアクセスしたかどうかを確認できます。
    ```kql
    // HR機密ファイルへの不正アクセスの可能性
    CloudAppEvents
    | where ActionType == "FileAccessed" and ActivityObjects has "HR-Confidential"
    | summarize count() by AccountUpn, ActionType
    ```
    たとえば、マーケティングのアカウントがHR機密ファイルにアクセスしていることがここで示された場合、それは調査すべきコンプライアンスの問題です（許可の範囲を超えているか、不正使用の可能性があります）。
  - *高度なクエリ:* **管理操作の監査:** 管理者のみが管理者レベルの操作を実行することを確認します。たとえば、すべてのExchangeメールボックスのエクスポートイベント（適切なActionTypeでCloudAppEvents経由でログに記録されている場合）が管理者ロールを持つアカウントによって実行されたことを確認します。次のように実行できます。
    ```kql
    // 管理者でないユーザーが管理操作を実行したかどうかを監査
    CloudAppEvents
    | where IsAdminOperation == false and ActionType in ("AddedMailboxPermission","ResetUserPassword","ChangedOrgSetting")
    | summarize Events=count() by AccountDisplayName, ActionType
    ```
    *(この仮説的なクエリでは、ActionTypeフィルターをログに記録された実際の管理アクションに置き換えてください。)* 管理者権限のないユーザー（IsAdminOperation == false）が管理者権限のようなアクションを試行または実行した場合、それは非準拠です。セキュリティチームは、それがどのように起こったか（ロールの割り当てミスか？バグか？何らかの形で成功した悪意のある試みか？）を確認する必要があります。これは、クラウドアプリにおける特権の境界が尊重され、違反がすぐにフラグ付けされて修正されるのに役立ちます。

### IdentityInfo
**スキーマの説明:** `IdentityInfo`テーブルは、さまざまなソース（Azure AD/Microsoft EntraやオンプレミスADなど）から収集されたユーザーアカウントに関する情報を提供します（[高度な検索スキーマのIdentityInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table#:~:text=The%20,)）。これは基本的に**IDの詳細のインベントリ**であり、各レコードはID（ユーザー）であり、アカウントの**表示名、UPN、Azure AD ObjectId、オンプレミスAD SID**（同期されている場合）、および**部署、役職、メール、市区町村、国**などのディレクトリ情報が含まれます（[高度な検索スキーマのIdentityInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table#:~:text=%60ReportId%60%20,)）（[高度な検索スキーマのIdentityInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table#:~:text=,)）。このテーブルは、他のデータを充実させる（ユーザーIDをわかりやすい名前や組織情報にマッピングする）のに最適であり、ユーザー属性（たとえば、特定の部署のすべてのアカウントや特定のプロパティを持つアカウントを見つける）によるコンプライアンスまたは脅威ハンティングにも役立ちます。以前は*AccountInfo*と呼ばれていました。

**ユースケース:**

- **セキュリティ調査:** 調査担当者は、インシデントに関与したユーザーの背景情報を取得するために、IdentityInfoをよく使用します。たとえば、アラートにユーザー`alice@contoso.com`が含まれている場合、調査担当者はアリスの部署、役職、アカウントが有効かどうかなどをすばやく取得して、影響または内部脅威の可能性を評価できます。
  - *基本的なクエリ:* 特定のユーザー（UPNまたはアカウントオブジェクトID別）のIDの詳細を取得します。
    ```kql
    // 特定のユーザーのID情報を取得
    IdentityInfo
    | where AccountUpn == "alice@contoso.com"
    ```
    これにより、アリスの完全なプロファイル（名前、メール、部署、役職、アカウントが有効かどうか（`IsAccountEnabled`）など）が返されます。彼女の役割（たとえば、彼女が財務部に所属しており、アラートが財務データへのアクセスに関するものであった場合）を知ることは、そのアクティビティが予期されたものであったかどうかを判断するのに役立ちます。
  - *高度なクエリ:* 複数のアカウントを含む調査を充実させます。たとえば、ログまたはアラートで複数のユーザーIDが見つかった場合、それらのIDをIdentityInfoと結合して、部署と役職を一度にリスト表示し、パターンがあるかどうかを確認できます（おそらくすべて同じ部署から、またはすべて新入社員）。
    ```kql
    // 疑わしいAccountObjectIdのリストをIDの詳細で強化
    let suspiciousUsers = datatable(AccountObjectId:string)["<ID1>", "<ID2>", "<ID3>"];
    suspiciousUsers
    | join IdentityInfo on AccountObjectId
    | project AccountDisplayName, AccountUpn, Department, JobTitle, IsAccountEnabled
    ```
    これにより、たとえば、ID1はアリス - 財務アナリスト、ID2はボブ - 営業担当者などが出力され、調査担当者はこれらのユーザーがターゲットにされた理由または関与した理由を評価できます。すべてが1つのチームからのものである場合、おそらくそのチームのデータがターゲットにされました。

- **脅威ハンティング:** ハンターはIdentityInfoをクエリして、リスクをもたらす可能性のある特定の基準を満たすアカウントを見つけることができます。たとえば、*古いアカウント*（有効になっているが使用されていないアカウント、または最近のログオンイベントがないアカウント）、または集中的な監視のための*高特権アカウント*。IdentityInfoは特権アカウントを直接ラベル付けしませんが、役職またはグループメンバーシップ（同期されている場合）でハンティングできます（ただし、グループ情報はこのテーブルに直接含まれていない可能性があり、SentinelのUEBAには類似のものがあるかもしれません）。
  - *基本的なクエリ:* Azure ADで*無効*になっているアカウント、または*有効になっていない*とマークされているアカウントで、ログにまだ表示されるもの（無効になっているアカウントの使用を示している可能性）を見つけます。まず、無効になっているアカウントを特定します。
    ```kql
    // 無効になっているユーザーアカウントをリスト表示（IsAccountEnabled = false）
    IdentityInfo
    | where IsAccountEnabled == false
    | project AccountDisplayName, AccountUpn, Department, LastUpdated=Timestamp
    ```
    脅威ハンターは、これらをサインインログと相互参照する可能性があります（無効になっているアカウントがログインしている場合、それは大きな問題です）。この基本的なクエリ自体も、コンプライアンス（退職者のアカウントが実際に無効になっていることを確認する）に役立ちます。
  - *高度なクエリ:* **シャドウ管理者ハンティング** - タイトルや部署では明らかに管理者ではないが、特権グループのメンバーであるアカウントを見つけます。オンプレミスADグループのメンバーシップがIdentityInfoのプロパティに取り込まれた場合（ExposureGraphNodesの**NodeProperties**が必要になるかどうかは不明）、複雑なアプローチでは、IdentityInfoをExposureGraphEdges/Nodesと結合してグループメンバーシップを取得します。たとえば、`JobTitle`に「Admin」が含まれていないが、ドメイン管理者のグループのメンバーであるアカウントを見つけます（これには、ExposureGraphEdgesを使用したグループの関係が必要になるか、利用できない場合は、UPNによる既知の管理者のカスタムリストが必要になる可能性があります）。より簡単なヒューリスティック：*パスワードの有効期限なし*またはその他のフラグ（存在する場合）を持つアカウントを見つけます（IdentityInfoにそのようなフラグが含まれているかどうかは不明；おそらく直接は含まれていません）。そうでない場合は、役割のキーワードを使用できます。
    ```kql
    // 管理者と見なされる役割を持つアカウントを特定
    IdentityInfo
    | where JobTitle contains "Admin" or Department contains "IT"
    ```
    （これは弱いプロキシです。可能であれば、他のテーブルを介してディレクトリグループ情報とより適切に関連付ける必要があります。）目的は、これらのアカウントの脅威ハンティングを他のログ（たとえば、これらの管理者アカウントのいずれかにリスクの高いログインがあったかどうかを確認する）に集中させることです。ここでの直接的な関連付けがなくても、ハンターはIdentityInfoから価値の高いアカウントのリストを生成し、サインインログまたはデバイスログのクエリで使用できます。

- **コンプライアンスチェック:** IdentityInfoは、コンプライアンスおよび監査シナリオに非常に役立ちます。たとえば、ユーザーアカウントの詳細が特定の基準を満たしていること（全員に部署とマネージャーが入力されているなど）、無効にする必要があるアカウント（たとえば、最終日が30日前であるが、まだ有効になっている）、またはデータ所在地コンプライアンスのために地域別のアカウントをリスト表示することを確認します。
  - *基本的なクエリ:* **孤立したアカウントのチェック:** 退職した可能性のあるアカウントで、まだ有効になっているものを特定します。アカウントが変更されたことが検出されたとき、または24時間ごとにIdentityInfoが更新される場合、1つのアプローチは、既知の退職者のリストを相互参照するか、最近のアクティビティがないことを使用することです。たとえば、60日間ログインしていない有効なアカウントを見つけます（IdentityLogonEventsとの結合が必要になるか、IdentityInfoで利用可能な最終ログインタイムスタンプを使用する必要がありますが、直接は利用できません）。簡略化されたコンプライアンスクエリとして：有効になっている（`IsAccountEnabled == true`）が、部署または役職がないすべてのアカウントをリスト表示します（サービスアカウントまたは不適切に管理されているアカウントを示している可能性があります）。
    ```kql
    // 部署または役職情報が欠落している有効なアカウント
    IdentityInfo
    | where IsAccountEnabled == true and (isempty(Department) or isempty(JobTitle))
    | project AccountDisplayName, AccountUpn, Department, JobTitle
    ```
    このようなアカウントは、アカウントメタデータの完全性に関する人事/ITポリシーに違反している可能性があり、またはサービスアカウントである可能性があり（その場合、適切な処理またはMFAの強制についてレビューする必要があります）。
  - *高度なクエリ:* **役割ベースのコンプライアンス:** 特権アカウント（グローバル管理者など）が特定の属性（多要素認証の強制やマネージャーの割り当てなど）を持っていることを確認します。これには、管理者アカウントの外部リストとの関連付けが必要になる場合があります。Azure ADロールから管理者AccountObjectId（`adminList`）のリストがあると仮定すると、それらのアカウントがIdentityInfoでMFAを持っているか（ここではフィールドではありません）、少なくともIT部門に属し、適切な役職を持っているかどうかを確認できます。
    ```kql
    // すべてのテナント管理者がIT部門にいることを相互確認
    let tenantAdmins = datatable(AccountObjectId:string)["<AdminID1>", "<AdminID2>"];
    tenantAdmins
    | join IdentityInfo on AccountObjectId
    | project AccountDisplayName, Department, JobTitle, IsAccountEnabled
    | where Department !contains "IT"
    ```
    これは、グローバル管理者のいずれかがIT部門にリストされていない場合（ITスタッフのみが管理者ロールを持つべきであるため、ポリシーに反する可能性があります）にフラグを立てます。同様に、すべてに対して`IsAccountEnabled`がtrueであるかどうかを確認できます（管理者アカウントが無効になっている場合、なぜまだロールを持っているのですか？など）。この種のクエリは、人事ロール、ITロール、および技術的な特権の間の整合性を保証するのに役立ちます。これは、最小特権とアカウント管理における重要なコンプライアンスの側面です。

### IdentityLogonEvents
**スキーマの説明:** `IdentityLogonEvents`テーブルは、オンプレミスActive Directory（Defender for Identity経由）とMicrosoftオンラインサービス（Defender for Cloud Apps経由）の2つの領域からの**認証イベント**をログに記録します（[高度な検索スキーマのIdentityLogonEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table#:~:text=The%20,)）。インタラクティブログイン、RDP、NTLM認証、Kerberos、およびクラウドサインイン（特にAADSignInEventsBetaに含まれていないもの）をカバーしています。主要なフィールドには、**ActionType**（ログオンアクティビティの種類）、**LogonType**（Windowsログオンのインタラクティブ、リモート、ネットワークなど（[高度な検索スキーマのDeviceLogonEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table#:~:text=,)））、**Protocol**（Kerberos、NTLM、OAuthなど）、**Account**の詳細（名前、UPN、SID、objectId）、およびデバイス情報（DeviceName、DeviceType、OSプラットフォーム）が含まれます（[高度な検索スキーマのIdentityLogonEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table#:~:text=Supported%20logon%20types.,account%20in%20Microsoft%20Entra%20ID)）（[高度な検索スキーマのIdentityLogonEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table#:~:text=book,Windows%2010%20and%20Windows%207)）。基本的に、これはオンプレミスADとクラウドからのシグナルを組み合わせた統合ログオンテーブルであり、包括的なID認証ハンティングを可能にします。

**ユースケース:**

- **セキュリティ調査:** ID関連のインシデント（オンプレミスADでの潜在的な横方向移動やブルートフォース、または疑わしいクラウドログインなど）を調査する場合、IdentityLogonEventsが頼りになります。たとえば、ユーザーのアカウントが侵害された可能性がある場合、調査担当者は問題の時間帯のそのユーザーのすべてのログオンイベント（オンプレミスADログオンとこのテーブルに該当するクラウドサインインの両方）を取得します。
  - *基本的なクエリ:* 特定のユーザーの最近のログオンイベントを取得して、失敗があったかどうか、どこから、どのような種類（たとえば、Kerberos対クラウドOAuth）であったかを確認します。たとえば：
    ```kql
    // ユーザーjdoeの最新のログオンイベント5件（オンプレミスまたはクラウド）
    IdentityLogonEvents
    | where AccountUpn == "jdoe@contoso.com"
    | sort by Timestamp desc
    | take 5
    | project Timestamp, ActionType, LogonType, Protocol, DeviceName, FailureReason
    ```
    これは、たとえば、ジョン・ドウがサーバーでNTLMログインに失敗し、その後見慣れないデバイスからクラウドログインに成功したことを示す可能性があります。調査担当者はこのタイムラインを使用して、疑わしい動作（攻撃者がクラウドからオンプレミスに移動するなど）を追跡できます。
  - *高度なクエリ:* **横方向移動**を調査します。たとえば、アラートが特定のユーザーが複数のマシンにログインしたことを示している場合（パスザハッシュシナリオ）、短時間でそのユーザーの異なるDeviceNameをクエリします。
    ```kql
    // 1時間以内にユーザーが複数のデバイスにログインしたかどうかを確認（横方向移動の可能性）
    IdentityLogonEvents
    | where AccountName == "ADMINISTRATOR" and Timestamp between (ago(1h) .. now())
    | summarize UniqueDevices=dcount(DeviceName), Devices=make_set(DeviceName)
    ```
    *ADMINISTRATOR*（または関心のある任意のアカウント）が同じ1時間以内に複数のデバイスでログオンを示している場合、それは危険信号です（予期される場合を除く）。調査担当者は、侵害のさらなる証拠についてこれらのデバイスに焦点を当てます。

- **脅威ハンティング:** IdentityLogonEventsを使用すると、ハンターはADでの**ブルートフォース攻撃、異常なログオン時間、レガシープロトコルの使用**、または異常なログオンタイプ（たとえば、サービスアカウントがインタラクティブログインを実行するなど、本来あってはならないこと）などのパターンを探すことができます。オンプレミスとクラウドの認証データの組み合わせにより、両方にまたがるパターン（たとえば、攻撃者が侵害されたアカウントをADとO365の両方で使用するなど）を検出できます。
  - *基本的なクエリ:* オンプレミスADでの**失敗したログオンの連続**（ブルートフォースの可能性が高い）を探します。たとえば、短期間に多数の失敗した認証イベント（ActionTypeには「LogonFailed」またはFailureReasonがnullでないものが含まれる可能性があります）を持つアカウントを見つけます。
    ```kql
    // 過去30分間に20回以上ログインに失敗したアカウント（ブルートフォースの可能性）
    IdentityLogonEvents
    | where Timestamp > ago(30m) and isnotempty(FailureReason)
    | summarize FailedCount=count() by AccountUpn
    | where FailedCount > 20
    ```
    これは、パスワード推測攻撃を受けているアカウントを特定します。このようなアカウントを見つけたハンターは、成功したものがあるかどうか、または同じソースが多数のアカウントにヒットしているかどうかを確認します。
  - *高度なクエリ:* **疑わしいログオンタイプ**を探します。たとえば、特定のアカウントにとって異常なLogonTypeです。サービスアカウントがインタラクティブにログオンすべきではないのに、ログオンした場合、それは兆候です。たとえば：
    ```kql
    // サービスアカウント（名前パターン別）によるインタラクティブまたはRDPログオン
    IdentityLogonEvents
    | where AccountName startswith "svc_" and LogonType in ("Interactive", "RemoteInteractive")
    | project Timestamp, AccountName, DeviceName, LogonType
    ```
    サービスアカウント（多くの場合、`svc_`または類似のプレフィックスが付いています）がインタラクティブまたはRDP経由でログオンした場合、攻撃者がそれらの資格情報を使用してピボットしている可能性があることを示している可能性があります。通常、これらのアカウントはサービスを実行するためだけに使用され、ログインはしないためです。これは、特権の高いサービスアカウントの潜在的な不正使用を追跡するのに役立ちます。

- **コンプライアンスチェック:** コンプライアンスの観点から見ると、IdentityLogonEventsは、認証ポリシーが遵守されていることを確認するのに役立ちます。たとえば、許可されていない場所でのNTLMの使用、特定の機密システムの営業時間外のログオン（ポリシーによって異なります）、またはすべての管理者ログオンが監査されていることなどです。また、アクセスポリシーに違反する可能性のあるアカウント（許可されていないネットワークからのログオンなど）を検出するのにも役立ちます。
  - *基本的なクエリ:* **レガシー認証の使用状況:** 多くの組織は、セキュリティとコンプライアンス上の理由から、NTLM認証を排除することを目指しています。NTLM（古いプロトコル）がまだログオンで使用されているかどうかを確認できます。
    ```kql
    // 過去24時間のNTLMとKerberosのログオン数（オンプレミスAD）
    IdentityLogonEvents
    | where Timestamp > ago(24h) and Protocol in ("NTLM","Kerberos")
    | summarize Count=count() by Protocol
    ```
    NTLMの数が有意である場合、Kerberos/モダン認証を優先するポリシーに非準拠です。デバイスまたはアカウントごとにさらにドリルダウンして、NTLMが発生している場所（古いシステムまたはそれを使用しているアプリケーションなど）を特定できます。
  - *高度なクエリ:* **特権アカウント**が承認された方法でのみログオンすることを確認します。たとえば、ドメイン管理者はドメインコントローラーまたはジャンプボックスにのみログオンすべきかもしれません。特権の高いアカウントが通常のワークステーションにログオンした場合、それはポリシーに反する可能性があります。特権アカウントのリスト（グループメンバーシップまたは命名規則による）がある場合は、それを使用します。
    ```kql
    // ドメイン管理者によるドメインコントローラー以外のマシンへのログオンを確認
    let domainAdmins = pack_array("DAlice", "DBob");  // ドメイン管理者アカウント名のリスト
    IdentityLogonEvents
    | where AccountName in (domainAdmins) and DeviceType != "DomainController" and LogonType == "Interactive"
    | project Timestamp, AccountName, DeviceName, LogonType
    ```
    ここで結果が出た場合、ドメイン管理者（DAliceまたはDBob）がDCではないマシンにインタラクティブにログオンしたことを意味します。多くのセキュリティポリシーでは、リスクがあるため禁止されています。このコンプライアンスクエリは、さらなるトレーニングまたは強制（管理者にジャンプサーバーの使用を促すなど）のために危険な動作にフラグを立てるのに役立ちます。別のコンプライアンスチェックとして、*サービスアカウントのみ*であるはずのアカウントによるインタラクティブログオンを検出できます（脅威ハンティングでバリアントを実行しました）。

### EmailAttachmentInfo
**スキーマの説明:** `EmailAttachmentInfo`テーブルには、Defender for Office 365（Exchange Online Protection）によって処理された**メールに添付されたファイル**に関する情報が含まれています（[高度な検索スキーマのEmailAttachmentInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table#:~:text=The%20,)）。各レコードはメールメッセージの添付ファイルを表し、親メールの識別子（**NetworkMessageId**とInternetMessageId）、送信者/受信者の情報、および添付ファイルの詳細（**FileName**、**FileType**（拡張子）、ファイル**SHA256ハッシュ**、ファイルサイズ、および脅威評価の結果（たとえば、マルウェアが検出されたかどうかを示す**ThreatTypes**、マルウェアファミリーの**ThreatNames**、使用された**DetectionMethods**））などのフィールドが含まれています（[高度な検索スキーマのEmailAttachmentInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table#:~:text=,)）（[高度な検索スキーマのEmailAttachmentInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table#:~:text=Microsoft%20Entra%20ID%20,)）。このテーブルは通常、悪意のある添付ファイルを調査したり、メールフロー内の特定のファイルを追跡したりするために、EmailEvents（メール自体をログに記録する）と組み合わせて使用されます。

**ユースケース:**

- **セキュリティ調査:** アラートまたはインシデントが悪意のあるメール添付ファイル（たとえば、マルウェアに感染したドキュメント）に関連する場合、調査担当者はEmailAttachmentInfoを使用してそのファイルの詳細を取得し、それが他にどこに現れた可能性があるかを追跡します。たとえば、特定の添付ファイルのハッシュが悪意のあることがわかっている場合、このテーブルでそのハッシュを検索して、それを受信したすべてのユーザーを見つけます。
  - *基本的なクエリ:* 疑わしいファイル（ハッシュまたは名前別）のすべてのインスタンスをメールで検索します。マルウェア添付ファイルのSHA256がある場合、次のようにクエリできます。
    ```kql
    // 特定の悪意のあるファイル（SHA256別）を運ぶメールを見つける
    EmailAttachmentInfo
    | where SHA256 == "<malicious-file-hash>"
    | project Timestamp, FileName, SenderFromAddress, RecipientEmailAddress, ThreatTypes
    ```
    これは、そのファイルがいつ、誰の間で送信されたか、そしてそれがフラグが立てられたかどうかを示しています（ThreatTypesは検出された場合に「Malware」を示す可能性があります）。これは、インシデントの範囲（1人だけが受信したのか、それとも多くの人が受信したのか）を把握するのに役立ちます。
  - *高度なクエリ:* 添付ファイルをメールと関連付けることで、フィッシングキャンペーンを調査します。たとえば、既知の悪意のある添付ファイルを含むメールを受信したすべての受信者と、彼らがそれをクリックしたかどうかをリスト表示します（UrlClickEventsまたは他のデータとの結合が必要になりますが、添付ファイル情報内では、少なくとも受信者とそれがブロックされたかどうかを取得できます）。別の角度：異なるメールの複数の添付ファイルが同じThreatName（マルウェアファミリー）を持つことがあります。特定のマルウェアとしてラベル付けされたすべての添付ファイルのハッシュを収集できます。
    ```kql
    // 特定のマルウェアファミリーに関連付けられたすべての添付ファイルのハッシュを見つける
    EmailAttachmentInfo
    | where ThreatNames has "Trickbot"  // マルウェア名の例
    | summarize CountEmails=dcount(NetworkMessageId), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by SHA256, FileName, ThreatNames
    ```
    これにより、Trickbotとして識別されたメール内のファイルハッシュのセット、それらが検出されたメッセージの数、およびタイムフレームが得られます。調査担当者はその後、これらのファイルがエンドポイント（DeviceFileEvents）で実行されたかどうかを確認したり、ブロックされたことを確認したりできます。

- **脅威ハンティング:** ハンターはEmailAttachmentInfoを使用して、検出をすり抜けた可能性のある悪意のある添付ファイルのパターンを検索したり、新しい脅威キャンペーンがメールでどのように現れているかを特定したりする場合があります。たとえば、送信されている異常なファイルの種類や、疑わしい名前の添付ファイルをハンティングします。
  - *基本的なクエリ:* メールで送信されている**実行可能ファイル**の添付ファイルを見つけます。*.exe*、*.scr*などは正当なビジネスコミュニケーションではめったに送信されないため、それらの存在は悪意のあるアクティビティまたはポリシー違反を示している可能性があります。たとえば：
    ```kql
    // メール添付ファイル内の実行可能ファイルまたはスクリプトファイルを探す（過去7日間）
    EmailAttachmentInfo
    | where Timestamp > ago(7d) and FileType in~ (".exe", ".dll", ".js", ".scr", ".bat")
    | project Timestamp, FileName, SenderFromAddress, RecipientEmailAddress, ThreatTypes
    ```
    ThreatTypesが空（マルウェアとしてフラグが立てられていないことを意味する）であっても、*.exe*添付ファイルを含むメールのリストは確認する価値があります。ハンターは、マルウェアとして検出されなかった*.exe*（ゼロデイ）を見つけて、積極的に調査する可能性があります。
  - *高度なクエリ:* **大量の疑わしい添付ファイル**を探します。たとえば、同じ添付ファイル名が多くの受信者に送信された場合（一般的なおとりファイルを使用したフィッシングである可能性があります）。KQLを使用して、多くの異なる受信者に送信された上位のFileNameを特定します。
    ```kql
    // 潜在的な大量フィッシング：多数の異なる受信者を持つ添付ファイル
    EmailAttachmentInfo
    | where Timestamp > ago(2d)
    | summarize RecipCount=dcount(RecipientEmailAddress) by FileName, SHA256, ThreatTypes
    | where RecipCount > 10 and isempty(ThreatTypes)  // AVによってフラグが立てられていないが、大量送信された
    ```
    これにより、広く配布されたが、必ずしもフィルターによってキャッチされたわけではないファイルが表面化します。添付ファイルが50個のメールボックスに表示され、フラグが立てられていない場合、脅威ハンターはそのファイルの本質を調査するでしょう（新たな脅威である可能性があります）。

- **コンプライアンスチェック:** コンプライアンスまたはポリシーの観点から、EmailAttachmentInfoを使用して、特定の種類のファイル（実行可能ファイルや機密文書など）がメールで送信されていないこと、またはDLPポリシーが有効であることを確認できます。また、メールによる大きなファイルの移動を追跡するためにも使用できます。
  - *基本的なクエリ:* **制限されたファイルの種類** - 会社のポリシーで特定のファイルの種類（たとえば、*.pst*ファイルやパスワードで保護されたzipファイル）をメールで送信することが禁止されている場合、それらをクエリできます。たとえば：
    ```kql
    // .pstファイルが添付ファイルとして送信されたかどうかを確認（ポリシー違反）
    EmailAttachmentInfo
    | where FileType == ".pst"
    | summarize TotalSent = count(), UniqueSenders=dcount(SenderFromAddress)
    ```
    これが何かを返す場合、メールボックスアーカイブがメールで送信されたことを意味し、これはデータ管理ポリシーに違反する可能性があります。同様に、*.zip*と暗号化の何らかの指標（ただし、暗号化されたファイルの検出は、ThreatTypesまたは利用可能な場合は検出方法にある可能性があります）を検索できます。
  - *高度なクエリ:* **データ漏洩監査** - たとえば、機密文書（ファイル名にキーワードが含まれているか、分類ラベルがある場合、それらが添付ファイル情報に伝播する場合）が組織外に送信されたかどうかを確認します。`RecipientEmailAddress`がドメインで終わらない場合は、外部受信者を示し、そのロジックを組み合わせることができます。
    ```kql
    // 潜在的なデータ漏洩：機密ファイルが外部受信者に送信された
    EmailAttachmentInfo
    | where FileName contains "Confidential" or FileName contains "Sensitive"
    | extend IsExternalRecipient = iff(RecipientEmailAddress !endswith "@contoso.com", "Yes", "No")
    | summarize Attachments=count() by FileName, Sender=SenderFromAddress, IsExternalRecipient
    | where IsExternalRecipient == "Yes"
    ```
    これは、名前に「Confidential」が含まれる添付ファイルで、contoso.com以外の人に送信されたものを見つけます。そのような発生ごとにコンプライアンスの問題（許可されていない場合）である可能性があり、DLPがそれをキャッチしたかどうかを確認する必要があります。明示的なラベルがなくても、大きなファイル名または疑わしいファイル名で*IsExternalRecipient == Yes*を確認することで、コンプライアンスチームはメールによるミスまたは悪意のあるデータ漏洩を捕捉するのに役立ちます。

### EmailEvents
**スキーマの説明:** `EmailEvents`テーブルは、各メールメッセージの経路とフィルタリングを網羅する**Microsoft 365メールイベント**をログに記録します（[高度な検索スキーマのEmailEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table#:~:text=The%20,)）。各レコードは通常1つのメールを表し、**NetworkMessageId**（メールの内部一意ID）、**InternetMessageId**（SMTP Message-ID）、送信者と受信者のアドレス、件名、およびメールに何が起こったか（配信ステータス、スパム/フィッシング判定（ActionTypeの一部として））などの詳細が含まれます。また、**EmailDirection**（Inbound、Outbound）やさまざまな送信元/宛先の情報、および**DeliveryLocation**や**ThreatTypes**（検出された場合）などのフィールドもログに記録します。基本的に、このテーブルはメールフロー（配信、ブロック、ドロップなど）を追跡し、メールのメタデータを分析するために使用されます。

**ユースケース:**

- **セキュリティ調査:** フィッシングインシデントを調査する場合、EmailEventsを使用して、フィッシングメールを配信したメールを見つけます。誰が送信したか、誰が受信したか、いつ、そして何が行われたか（配信されたか、フィルタリングされたか）。アナリストは、件名とネットワークメッセージIDを取得して、添付ファイルとURLデータを関連付けるためにも使用します。
  - *基本的なクエリ:* 件名または送信者/受信者で特定のメールを検索します。たとえば、役員が「請求書」という件名の疑わしいメールを報告した場合、調査担当者は次のように検索できます。
    ```kql
    // 特定の件名を持つメールを検索
    EmailEvents
    | where Subject has "Invoice" and RecipientEmailAddress == "ceo@contoso.com"
    | project Timestamp, SenderFromAddress, RecipientEmailAddress, DeliveryLocation, EmailDirection
    ```
    これにより、CEOが請求書関連のメールを受信したかどうか、誰から、そして受信トレイに届いたか、フィルタリングされたか（DeliveryLocationは受信トレイ、迷惑メール、検疫などを示す可能性があります）がわかります。これは、報告されたメールが存在するかどうかとその経路を確認するのに役立ちます。
  - *高度なクエリ:* 同じ特性を持つすべてのメールを見つけることで、フィッシングキャンペーンを追跡します。1通の悪意のあるメールが見つかった場合は、そのNetworkMessageIdまたはInternetMessageIdを識別子として使用して、関連するメッセージを見つけます（複数の受信者がいる場合、同じInternetMessageIdで複数のNetworkMessageIdが発生することがあります）。たとえば：
    ```kql
    // InternetMessageIdでフィッシングメールのすべての受信者を取得
    let phishId = EmailEvents
                  | where Subject == "[Payment Notice]" and SenderFromDomain == "evil.com"
                  | project InternetMessageId
                  | take 1;
    EmailEvents
    | where InternetMessageId in (phishId)
    | project Timestamp, SenderFromAddress, RecipientEmailAddress, DeliveryLocation, ThreatTypes
    ```
    これにより、そのメールのすべてのインスタンス（おそらく多くの人に送信された）が見つかります。調査担当者は、他に誰が受信したか、そしてそれがブロックされたかどうか（ThreatTypesはフィッシングとしてマークされたかどうかを示す可能性があります）を確認できます。一部が（受信トレイに）届いた場合、それらのユーザーには緊急の対応（ZAPによる強制的な検疫やユーザー教育など）が必要です。

- **脅威ハンティング:** ハンターはEmailEventsをクエリして、アラートをトリガーしなかった可能性のある悪意のあるパターンを明らかにします。たとえば、新しいドメインからのメールの急増、疑わしいキーワードを含む多数のメール、または内部ユーザーにとって異常な送信者などです。
  - *基本的なクエリ:* 1つの内部アカウントからの**大量のメール送信**（侵害されたアカウントが内部スパムを送信している可能性がある）を検索します。たとえば、短時間で異常に多数の受信者にメールを送信した内部送信者がいるかどうかを確認します。
    ```kql
    // 多数の受信者に送信している内部アカウント（侵害されたアカウントによるスパムの可能性）
    EmailEvents
    | where EmailDirection == "Outbound" and SenderFromDomain == "contoso.com"
    | summarize RecipCount=dcount(RecipientEmailAddress), LastSeen=max(Timestamp) by SenderFromAddress
    | where RecipCount > 50
    ```
    内部ユーザーアカウントが最近50人以上の異なる受信者に送信していることが判明した場合、それは疑わしいです（特に通常そうしない場合）。脅威ハンターはそのアカウントが侵害されていないか調査します。
  - *高度なクエリ:* 配信された（つまり、フィルターをバイパスした可能性がある）受信メールの件名で特定のキーワードを探すことで、**標的型フィッシング**を特定します。たとえば：
    ```kql
    // 潜在的なフィッシング：一般的なフィッシング件名キーワードを含み、検出されていない配信済みメールを探す
    EmailEvents
    | where EmailDirection == "Inbound" and DeliveryLocation == "Inbox"
      and Subject matches regex @"(?i)urgent|password|verify|action required"
      and isempty(ThreatTypes)
    | project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress
    ```
    これは、件名に典型的なフィッシング用語（「緊急」、「対応が必要」など）を含み、マルウェア/フィッシングとして分類されずに受信トレイに届いたメール（ThreatTypesが空）を抽出します。ハンターはこれらの件名と送信者を確認できます。EOPが見落としたフィッシング試行（少量の送信または巧妙に作成されたため）が見つかる可能性があります。これは、自動フィルターが見落とした可能性のあるものを捉える方法です。

- **コンプライアンスチェック:** EmailEventsは、メールの使用ポリシー（たとえば、個人アカウントへの自動転送の禁止、機密情報の大量メール送信の禁止など）が遵守されていることを確認したり、コンプライアンスレポートのメトリック（暗号化されたメールの数、スパムとしてブロックされたメールの数など、アンチスパムコンプライアンスに関連する可能性のあるもの）を収集したりするなど、コンプライアンスシナリオに役立ちます。
  - *基本的なクエリ:* **外部転送のチェック:** 多くの組織では、データ保護のために企業メールの個人アドレスへの自動転送を禁止しています。コンプライアンスを確認するために、ユーザーが同じ外部アドレスに大量のメールを送信しているかどうかを確認できます（転送または手動によるデータ漏洩を示している可能性があります）。たとえば、各内部ユーザーが*@gmail.comアドレスに送信したメールの数をカウントします。
    ```kql
    // 潜在的な自動転送の検出：内部から外部へのパターン
    EmailEvents
    | where EmailDirection == "Outbound" and RecipientEmailAddress !endswith "@contoso.com"
    | summarize ExternalEmails=count() by SenderFromAddress, RecipientDomain = tostring(split(RecipientEmailAddress, "@")[1])
    | where ExternalEmails > 100 and RecipientDomain endswith "gmail.com"
    ```
    これは、bob@contoso.comがgmail.comアドレスに300通のメールを送信したことを示す可能性があります。これは、個人アカウントへの自動転送である可能性があります。コンプライアンスは、それが承認された例外であるかポリシー違反であるかを調査できます。
  - *高度なクエリ:* **暗号化/機密性コンプライアンス:** O365メッセージ暗号化または秘密度ラベルを使用している場合、送信される機密情報が常に暗号化されていることを確認したい場合があります。EmailEventsはメールが暗号化されたかどうかを直接示さないかもしれませんが、秘密度ラベルまたは特定のヘッダーが適用されたかどうかを示す可能性があります。または、特定の分類（ThreatTypesまたは他のフィールドに設定されている場合）でマークされたメールがクリアで送信されたかどうかを確認します。それがない場合、別のアプローチ：特定のキーワード（「SSN」または「Confidential」など）を含むすべてのメールがDLPによってキャッチされたことを確認します（DLPルールを示すActionTypeとしてEmailEventsに表示される可能性があります。そうでない場合は、統合されている場合はCloudAppEvents経由でDLPイベントが必要になる可能性があります）。簡単なチェック：
    ```kql
    // 件名/本文に「Confidential」を含むメールが外部に暗号化されずに送信されたかどうかを確認
    EmailEvents
    | where EmailDirection == "Outbound" and DeliveryLocation == "Delivered"
      and (Subject has "Confidential" or Subject has "Sensitive")
      and RecipientEmailAddress !endswith "@contoso.com"
      and isempty(ThreatTypes)  // DLPによってブロックまたは変更されていない（そうであれば脅威としてタグ付けされると仮定）
    ```
    これは決定的な方法ではありませんが、結果が出た場合、コンプライアンスはそれらのメールを確認して、機密情報が漏洩していないことを確認する必要があるかもしれません。より直接的なコンプライアンスクエリは、DLPによってブロックされたすべてのメールをリスト表示することです（DLPイベントがThreatTypesまたは「DLPBlock」のような特定のActionTypeとして表示される場合 - それらはEmailEventsまたは配信後に削除された場合はEmailPostDeliveryEventsにログに記録される可能性があります）。たとえば、機密情報のためにブロックされたメールの数をカウントして、データ保護ポリシーの遵守状況を報告します。

### EmailPostDeliveryEvents
**スキーマの説明:** `EmailPostDeliveryEvents`テーブルは、メールボックスに配信された**後のメールに対するセキュリティ関連のアクション**をログに記録します（[高度な検索スキーマのEmailPostDeliveryEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailpostdeliveryevents-table#:~:text=The%20,)）。これには、自動修復（たとえば、**ZAP** - ゼロ時間自動削除が最初の配信後にフィッシングメールを受信トレイから削除する）、手動修復アクション（管理者が検疫から削除または解放する）、またはユーザーアクション（ユーザーがフィッシングを報告するなど）が含まれます。主要なフィールドには、メールの識別子（NetworkMessageId、InternetMessageId）、実行された**アクション**（たとえば、迷惑メールに移動、削除、検疫から解放）、**ActionType**（それをトリガーした原因：たとえば、Phish ZAP、Malware ZAP、手動修復）（[高度な検索スキーマのEmailPostDeliveryEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailpostdeliveryevents-table#:~:text=,)）、それをトリガーした人（**ActionTrigger** - 管理者対システム）、およびアクションの結果が含まれます（[高度な検索スキーマのEmailPostDeliveryEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailpostdeliveryevents-table#:~:text=,)）。基本的に、このテーブルは、配信*後*にメールに何が起こったか、特に後で悪意のあるものとしてフラグが立てられたり、移動されたりした場合に確認するために使用されます。

**ユースケース:**

- **セキュリティ調査:** メールが配信された後、システム（または管理者）によって削除された場合、調査担当者はEmailPostDeliveryEventsを見てそのタイムラインを理解します。たとえば、ユーザーがフィッシングメールを報告した後、管理者はすべてのメールボックスからそれを削除するスクリプトを実行する可能性があります。そのアクションはここに表示されます。これは、悪意のあるメールが封じ込められたかどうかを確認するのに役立ちます。
  - *基本的なクエリ:* 特定のメール（NetworkMessageIdまたは件名別）がZAPまたは他の手段によって削除されたかどうかを確認します。たとえば、既知のNetworkMessageIdを持つフィッシングメールを調査する場合：
    ```kql
    // 特定のメールの配信後のアクションを確認
    EmailPostDeliveryEvents
    | where NetworkMessageId == "<message-id-guid>"
    | project Timestamp, Action, ActionType, ActionTrigger, RecipientEmailAddress, ActionResult
    ```
    これにより、たとえば、特定の時間に、メールが`MovedToDeletedItems`、`Phish ZAP`によって自動的に、結果`Succeeded`になったことがわかります。調査担当者は、メールが最初に配信されたが、その後ZAPによってユーザーの受信トレイから削除されたことを知ることができます。
  - *高度なクエリ:* ZAPアクションがどれほど広範囲に及んだかを確認します。たとえば、フィッシングが削除された場合、それを削除されたすべての受信者をリスト表示します。必要に応じて、EmailEventsと結合して件名または送信者を取得できます。たとえば：
    ```kql
    // ZAPされたフィッシングメールの受信者リスト（InternetMessageId別）
    let zapMsg = EmailPostDeliveryEvents
                  | where ActionType == "Phish ZAP"
                  | project InternetMessageId, NetworkMessageId;
    zapMsg
    | join (EmailEvents | project InternetMessageId, Subject, SenderFromAddress) on InternetMessageId
    | join kind=inner (EmailPostDeliveryEvents | where ActionType == "Phish ZAP") on InternetMessageId
    | project Timestamp, Subject, SenderFromAddress, AffectedRecipient=RecipientEmailAddress, ActionResult
    ```
    これは、ZAPされたメールの受信者のリストを生成します（EmailEventsは、個別に送信された場合、同じInternetMessageIdに対して複数のNetworkMessageIdを示す可能性があるため）。これにより、範囲が確認されます。調査担当者は、すべてのコピーが対処されたことを確認します。

- **脅威ハンティング:** ハンターは、配信後のクリーンアップのパターンについてEmailPostDeliveryEventsを調べることがあります。これは、後でキャッチされた見逃されたフィッシングを示している可能性があります。たとえば、頻繁なPhish ZAPアクションは、一部のフィッシングが最初のフィルターを通過していることを示している可能性があります。また、**ユーザーレポート**（ユーザーレポートがここにログに記録されている場合、おそらくAction="UserReported"、ActionTrigger = userとして）もハンティングする可能性があります。
  - *基本的なクエリ:* **ZAPの傾向**（たとえば、過去1週間に発生したフィッシングZAPの数）を検索します。これは、最初に通過したフィッシングの量を示している可能性があります。
    ```kql
    // 日ごとのPhish ZAPアクション数（過去7日間）
    EmailPostDeliveryEvents
    | where Timestamp > ago(7d) and ActionType == "Phish ZAP"
    | summarize ZAPs=count() by bin(Timestamp, 1d)
    ```
    ハンターは、特定の日にスパイクがあるかどうかを確認します。これは、キャンペーンがすり抜けて、その後大量に削除されたことを意味します。その後、それらのメールが何であったか（上記のようにEmailEventsと結合）にピボットして、キャンペーンの特性を分析し、フィルタリングを改善する可能性があります。
  - *高度なクエリ:* **ZAPさえも回避した可能性のある悪意のあるメール**を特定します。1つのヒューリスティック：対応するZAPアクションのないユーザーによるフィッシングの報告を探します。ユーザーが報告したが、システムが自動的に削除しなかった場合、それはギャップである可能性があります。ユーザーレポートがログに記録されている場合（このテーブルまたは別の監査ログにAction="UserReported"または類似のものとして表示される可能性があります）、次のように実行できます。
    ```kql
    // ZAPされなかったユーザー報告のフィッシング
    let reported = EmailPostDeliveryEvents
                    | where Action == "UserReported" or ActionTrigger == "User"
                    | project NetworkMessageId, ReportTime = Timestamp;
    let zapped = EmailPostDeliveryEvents
                 | where ActionType contains "ZAP"
                 | distinct NetworkMessageId;
    reported
    | where NetworkMessageId !in (zapped)
    | join (EmailEvents | project NetworkMessageId, SenderFromAddress, Subject) on NetworkMessageId
    | project ReportTime, Subject, SenderFromAddress, ReportedBy = RecipientEmailAddress
    ```
    このクエリは、ユーザーがフィッシングとして報告したが、ZAPされなかった（つまり、システムが自動的に削除しなかった）メールを見つけます。これらは見逃されたフィッシングである可能性があり、脅威ハンターはこれらのメールをレビューして、フィルターがそれらを見逃した理由を確認し、おそらくブロックを追加したり、認識を高めたりするでしょう。

- **コンプライアンスチェック:** コンプライアンスの観点から見ると、EmailPostDeliveryEventsは、特定の手順が実行されたことを検証するのに役立ちます。たとえば、すべての悪意のあるメールがクリーンアップされたこと（未削除のものが残っていないこと）、または監査のためにフィッシングへの対応を文書化することなどです。また、組織のDLPまたは脅威対応ポリシー（たとえば、X時間以内に悪意のあるメールを削除するなど）が実施されていることを示すのにも役立ちます。
  - *基本的なクエリ:* **削除の検証:** ポリシーで、確認されたすべてのフィッシングメールはメールボックスから削除する必要があると定められている場合、既知のフィッシングメール（おそらくEmailEventsにThreatTypes "Phish"が存在することによって）に対応する削除アクションが*なかった*かどうかを確認します。簡単なチェック：フィッシングとマークされたすべてのメールが実際に移動または削除されたことを確認します（ActionはPhish ZAPまたは検疫に移動されたなど）。たとえば：
    ```kql
    // すべてのフィッシング判定メールに配信後のアクションがあったことを確認
    let phishEmails = EmailEvents | where ThreatTypes has "Phish" | distinct NetworkMessageId;
    phishEmails
    | join kind=leftanti (EmailPostDeliveryEvents | distinct NetworkMessageId) on NetworkMessageId
    ```
    これがNetworkMessageIdを返す場合、EmailEventsでフィッシングとしてフラグが立てられたメールが配信後のアクションに表示されなかったことを意味します（おそらく配信前にブロックされたか、最悪の場合、配信されて削除されなかった）。コンプライアンスは、後続のアクションなしに配信されたものがないことを確認する必要があります。結果が見つかった場合は、アクションが見落とされていないか確認する必要があります。
  - *高度なクエリ:* **検疫からの解放の監査:** ポリシーで、検疫されたメールの解放が制限されている場合（たとえば、管理者のみが可能、または正当な理由が必要）、このテーブルを使用して解放を監査します。たとえば、検疫から解放されたすべてのメールと、誰によって解放されたかをリスト表示します（ActionTriggerは管理者を示す可能性があります）。
    ```kql
    // 検疫から解放されたメールの監査
    EmailPostDeliveryEvents
    | where Action == "MessageReleased" or Action has "Released"
    | project Timestamp, ReleasedBy=ActionTrigger, Recipient=RecipientEmailAddress, ActionResult
    ```
    これは、検疫されたメールがいつ、どのように解放されたかを示しています。ReleasedByが管理者アクションを示す場合、コンプライアンスは適切な承認があったかどうかを相互検証できます。「User」（許可されている場合）を示す場合、ポリシーでユーザーが自分の検疫されたメールを解放すべきではないと定められている場合、コンプライアンスはフラグを立てる可能性があります。基本的に、検疫解放の制御が遵守されているかどうかを確認しています。これは、EmailEventsと結合して、レポートのためにメールの内容（件名、送信者）を知ることで拡張できます。

### EmailUrlInfo
**スキーマの説明:** `EmailUrlInfo`テーブルには、Defender for Office 365によって処理された**メールおよび添付ファイルで見つかったURL**に関する情報が含まれています（[高度な検索スキーマのEmailUrlInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table#:~:text=The%20,)）。各レコードは、メール（本文、件名、または添付ファイル内（PDFなどのリンク付き）にさえある）から抽出されたURLを表します。主要なフィールドには、**NetworkMessageId**（特定のメールへのリンク）、完全な**Url**、**UrlDomain**（URLのホスト部分）、およびURLがメールのどこにあったかを示す**UrlLocation**（たとえば、本文、ヘッダー、添付ファイル、またはスキャンされたQRコード画像から来た場合は「QRCode」（[高度な検索スキーマのEmailUrlInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table#:~:text=,)）（[高度な検索スキーマのEmailUrlInfoテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table#:~:text=To%20hunt%20for%20attacks%20based,URLs%20extracted%20from%20QR%20codes)））が含まれます。このテーブルは、特にフィッシング調査で、メール内の悪意のあるリンクを特定し、それらを複数のメッセージにわたってピボットするのに役立ちます。

**ユースケース:**

- **セキュリティ調査:** フィッシングメールが疑われる場合、調査担当者はそこからURLを抽出して、それらがどこを指しているか（既知の悪意のあるものであるかどうか）を確認します。EmailUrlInfoは、メールを手動で解析する必要なく、それらのリンクを提供します。たとえば、ユーザーがリンクをクリックした場合、そのリンクが何であったかを知りたいでしょう。ユーザーのメール（EmailEventsまたはUrlClickEvents経由）からNetworkMessageIdを使用することで、URLを取得できます。
  - *基本的なクエリ:* 特定のメールのNetworkMessageId（またはフィルタリングするための既知の件名/送信者）を指定して、そのメールに存在するすべてのURLを取得します。
    ```kql
    // 件名で特定のメールからURLを取得
    let msg = EmailEvents
                  | where Subject == "Action Required: Update Account"
                  | project NetworkMessageId;
    EmailUrlInfo
    | where NetworkMessageId in (msg)
    | project Url, UrlDomain, UrlLocation
    ```
    これにより、`http://contoso-updates.com/verify`ドメイン`contoso-updates.com`が本文にあるなどのリストが表示されます。調査担当者はその後、これらのドメインを脅威インテリジェンスと照らし合わせたり、他のメールに現れるかどうかを確認したりできます。
  - *高度なクエリ:* 同じフィッシングURLが複数の人に送信されたかどうかを判断します。たとえば、1つのフィッシングメールから既知の悪意のあるURLドメインを取り出し、そのドメインからのURLを含むすべてのメールを見つけます。
    ```kql
    // 疑わしいドメインからのURLを含むすべてのメールを見つける
    EmailUrlInfo
    | where UrlDomain == "contoso-updates.com"
    | join EmailEvents on NetworkMessageId
    | project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url
    ```
    これにより、URL情報がメールの詳細と関連付けられます。調査担当者は、その偽のドメインを使用したフィッシングキャンペーンの範囲を確認するのに役立ちます。10人がそのリンクを含むメールを受信した場合、全員に警告するか、メールを削除する必要があります。

- **脅威ハンティング:** ハンターはEmailUrlInfoを使用して、フィッシングやその他の悪意のある意図を示す可能性のある**URLのパターン**を検索できます。たとえば、新しく見られたドメイン、または特定の疑わしい文字列（「login」や「verify」に非公式ドメインが加わったものなど）を含むURL、またはIPアドレスがURLとして現れる場合（多くの場合、悪い兆候）などです。
  - *基本的なクエリ:* メール内の**プレーンなIPアドレスであるURL**（たとえば、`http://123.456...`は多くの場合疑わしい）を検索します。
    ```kql
    // ベアIPアドレスを使用するメールURLを探す（悪意のある可能性）
    EmailUrlInfo
    | where Url matches regex @"http[s]?://\d+\.\d+\.\d+\.\d+"
    | summarize CountEmails=dcount(NetworkMessageId) by Url
    ```
    そのようなURLが表示された場合、おそらく誰かが直接IPリンク（正当なメールではまれです）を含むメールを送信しました。ハンターはそれらを確認します（マルウェアのダウンロードを指している可能性があります）。
  - *高度なクエリ:* メールURL内の**タイポスクワッティングドメイン**を探します。たとえば、あなたの会社ドメインや一般的なサイトに似ているが、正確ではないドメイン（「micros0ft.com」やcontoso.comの代わりに「contoso-security.com」など）をハンティングします。ヒューリスティック：ドメインに「contoso」という文字列が含まれているが、正確なcontoso.comではないURLを見つけます。
    ```kql
    // 'contoso'に類似する可能性のあるタイポスクワットドメインを探す
    EmailUrlInfo
    | where UrlDomain contains "contoso" and UrlDomain != "contoso.com"
    | summarize Examples=count() by UrlDomain
    | sort by Examples desc
    ```
    これにより、「contoso-login.com」のようなドメインが表示される可能性があり、これはフィッシングで使用される可能性があります。ハンターはその後、それらのドメインの評判を確認したり、そのようなリンクを受信した人を探したりできます。これは、会社のブランドを模倣した標的型フィッシング試行をプロアクティブに特定します。

- **コンプライアンスチェック:** EmailUrlInfoはセキュリティのためにより多く使用されますが、ユーザーが特定のカテゴリのコンテンツのターゲットにされているかどうかを追跡したり、クリック可能なリンク（セーフリンク）のロギングが機能していることを確認したりすることで、コンプライアンスにも役立ちます。おそらくコンプライアンスは、すべてのメールで送信されたURLがスキャンされていることを保証したいでしょう（このテーブルにそれらがあることは、スキャンされていることを意味します）。別の観点：特定の種類のリンク（たとえば、個人のクラウドストレージリンクが送信されている）に対するポリシーがある場合、それをクエリできます。
  - *基本的なクエリ:* **個人用ストレージリンクの使用状況:** 会社のポリシーで、仕事用のファイルに個人のDropbox/Googleドライブを使用しないように定められている場合、送信メールでそれらのドメインを検索できます。
    ```kql
    // 送信メール内の個人用ファイル共有リンクを確認
    EmailUrlInfo
    | where UrlDomain in ("dropbox.com","drive.google.com","wetransfer.com")
      and NetworkMessageId in (EmailEvents | where EmailDirection == "Outbound" | select NetworkMessageId)
    | summarize count() by UrlDomain
    ```
    これが多数のリンクを示す場合、従業員は個人用クラウドリンクを介してファイルを共有することでポリシーに違反している可能性があります。コンプライアンスはそれを使用して、代替方法を教育または強制することができます。
  - *高度なクエリ:* **フィッシング対策のカバレッジ:** セキュリティ標準への準拠のために、組織は検出およびブロックされた悪意のあるURLの数を報告する必要がある場合があります。EmailUrlInfoとUrlClickEventsは、セーフリンクが機能しているかどうかを示すことができます。1つのアプローチ：後でフラグが立てられた（セーフリンククリック判定）、しかし最初は存在していたURLを特定します。または、メール内のユニークなURLドメインを単純にカウントし、悪意のあるものとして分類されたものの数を調べます（EmailEventsのThreatTypes、またはそれらのURLが「Blocked」のUrlClickEventsに表示される場合）。ThreatTypesに「PhishURL」が含まれていない場合は、UrlClickEventsと関連付ける必要があるかもしれません。簡潔にするために：
    ```kql
    // 既知の悪意のあるドメイン（TIリストから）がメールに現れたことがあるかどうかを確認
    let badDomains = datatable(domain:string)["evil.com","malicious.org"];
    EmailUrlInfo
    | where UrlDomain in (badDomains)
    | distinct UrlDomain, NetworkMessageId
    ```
    既知の悪意のあるドメインがメールで見つかった場合、コンプライアンスはそれらがキャッチされたかどうかを尋ねます。EmailEventsでそれらのNetworkMessageIdを相互確認して、それらがブロックされたか配信されたかを確認します。これはセキュリティに関するものですが、これらのインシデントを報告することはインシデント管理プロセスへの準拠の一部です。一般的に、コンプライアンスはすべてのメールリンクがスキャンされることを義務付けるかもしれません - このデータを利用できることはそのスキャンニングの証拠です。

### UrlClickEvents
**スキーマの説明:** `UrlClickEvents`テーブルは、ユーザーがメール、Teams、またはOfficeアプリで**セーフリンクをクリックしたイベント**を記録します（[高度な検索スキーマのUrlClickEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table#:~:text=)）。セーフリンクは、クリック時にチェックするためにURLをスキャンしてラップする機能です。各エントリには、クリックの**タイムスタンプ**、クリックされた完全な**Url**、セーフリンクによってクリックが許可されたかブロックされたかを示す**ActionType**（例：ClickAllowed、ClickBlocked）（[高度な検索スキーマのUrlClickEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table#:~:text=,)）、クリックしたユーザーの**AccountUpn**、**Workload**（クリックがメール、Teams、またはOfficeアプリケーションからのものかどうか）（[高度な検索スキーマのUrlClickEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table#:~:text=list%20,)）、**NetworkMessageId**（メールからの場合、そのメールへのリンク）、および脅威判定情報（**ThreatTypes**（悪意のあるもの、フィッシング）や**DetectionMethods**など）が含まれます。また、ユーザーのデバイスのパブリックIPと、警告を*クリックして進んだ*かどうか（IsClickedThrough == trueは、セーフリンクの警告を無視して進んだことを意味します）（[高度な検索スキーマのUrlClickEventsテーブル - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table#:~:text=the%20clicked%20link%2C%20generated%20by,0)）もログに記録します。このテーブルは、フィッシング攻撃に対するユーザーの行動を理解し、セーフリンクの効果を測定するのに非常に重要です。

**ユースケース:**

- **セキュリティ調査:** ユーザーが侵害された場合、またはフィッシング攻撃に引っかかった場合、UrlClickEventsは悪意のあるリンクをクリックしたかどうかを確認できます。たとえば、フィッシングメールのインシデント後、調査担当者はこのテーブルを確認して、誰がフィッシングURLをクリックしたか、セーフリンクがそれをブロックしたか、ユーザーが警告を無視したかを確認します。
  - *基本的なクエリ:* 特定のユーザーが最近悪意のあるリンクをクリックしたかどうかを確認します。たとえば、ボブがフィッシングメールを受信した場合、彼はそれをクリックしましたか？
    ```kql
    // ボブによる最近のクリックで、悪意のあるものとして分類されたもの
    UrlClickEvents
    | where AccountUpn == "bob@contoso.com" and ThreatTypes contains "Phish"
    | project Timestamp, Url, ActionType, IsClickedThrough, Workload
    ```
    これは、ボブが悪意のあるものとしてフラグが立てられたリンクをクリックしたことを示しています。ActionTypeが「ClickBlocked」であり、IsClickedThroughが1の場合、ボブは警告されましたが、それでも続行した（つまり、ブロックをクリックして進んだ）ことを意味します。これは、ユーザーの行動を判断するための調査における重要な証拠です。
  - *高度なクエリ:* 特定のフィッシングキャンペーンについて、リンクをクリックしたすべてのユーザーを特定します。フィッシングメールのNetworkMessageIdまたはURL自体がある場合は、それによってクエリできます。たとえば、URLドメインを使用します。
    ```kql
    // フィッシングドメイン「contoso-updates.com」のリンクをクリックしたユーザーのリスト
    UrlClickEvents
    | where Url contains "contoso-updates.com" and ThreatTypes has "Phish"
    | summarize ClickCount=count(), FirstClick=min(Timestamp) by AccountUpn, ActionType, IsClickedThrough
    ```
    これにより、メールからそのフィッシングドメインを訪問しようとしたユーザーと、セーフリンクがそれらをブロックしたかどうか、またはしなかったかが明らかになります。調査担当者は、どのユーザーにフォローアップするか（特に許可された脅威をクリックして進んだ場合）を知ることができます。

- **脅威ハンティング:** UrlClickEventsは、ユーザーが潜在的に悪意のあるリンクとどのようにやり取りしたかを直接示すため、ハンティングに最適です。ハンターは、ユーザーが警告をクリックして進んだパターン、または新しく見られたドメインへの大量のクリックなどを検索できます。これは基本的に「誰が怪しいものとやり取りしているか」を示しています。
  - *基本的なクエリ:* **セーフリンクのバイパス**（ユーザーが警告をクリックして進んだすべてのインスタンス）を検索します。これらのイベントには、IsClickedThrough = 1があり、通常ActionTypeは「ClickAllowed」（警告を無視したことを意味します）です。
    ```kql
    // 過去30日間にユーザーがセーフリンクの警告を無視してクリックしたすべてのインスタンス
    UrlClickEvents
    | where Timestamp > ago(30d) and IsClickedThrough == true
    | project Timestamp, AccountUpn, Url, ThreatTypes, Workload
    ```
    脅威ハンターはこれらを確認します。ThreatTypesが悪意のあるURLを示しており、ユーザーがそれでも続行した場合、それらのユーザーは標的を絞ったセキュリティトレーニングまたはアカウント/デバイスのフォローアップチェックが必要になる可能性があります。
  - *高度なクエリ:* **トレンドの悪意のあるURL**（たとえば、組織全体で特定のURLまたはドメインが多数のクリックを受けている）を探します。これは、広範なフィッシングキャンペーンを示している可能性があります。
    ```kql
    // 過去1週間で最もクリックされた悪意のあるURLドメイン上位5件
    UrlClickEvents
    | where Timestamp > ago(7d) and ThreatTypes != ""  // 脅威判定が存在する場合のみ（悪意のあるもの）
    | summarize Clicks=count() by UrlDomain = tostring(parse_url(Url).Host)
    | sort by Clicks desc
    | take 5
    ```
    これにより、たとえば、`contoso-updates.com`が10回クリックされ、`office-secure-login.net`が8回クリックされたなどが示されます。これらを見たハンターは、（上記のように）誰がクリックしたかをドリルダウンし、これらのドメインを脅威インテリジェンスまたはブロックに追加することもできます。これは基本的に、その週で最も成功したフィッシングの誘いを特定することです。

- **コンプライアンスチェック:** UrlClickEventsは、セキュリティ意識（トレーニングへの準拠）の指標として役立ちます。たとえば、時間の経過とともにユーザーがフィッシングリンクをクリックする回数が減っているかどうかなどです。また、セーフリンクが運用されていることを確認するのにも役立ちます（データが何も入ってこない場合は問題です）。さらに、コンプライアンスのために、ユーザーが許可されていないカテゴリのサイトをクリックしていないことを確認するために使用できます（ThreatTypesがマルウェア/フィッシングだけでなく、ブロックされたURLカテゴリもカバーしている場合ですが、通常、セーフリンクは悪意のあるコンテンツに焦点を当てています）。
  - *基本的なクエリ:* **ユーザー意識の指標:** 四半期ごとに警告をクリックして進んだユーザーの数をカウントします。コンプライアンスの義務としてこの数を減らす必要がある場合、それを追跡できます。
    ```kql
    // セーフリンクの警告を無視した異なるユーザーの数（月ごと）
    UrlClickEvents
    | where IsClickedThrough == true
    | summarize UsersWhoClickedThrough=dcount(AccountUpn) by Month=bin(Timestamp, 30d)
    ```
    セキュリティトレーニングの後、この数が減少している場合、コンプライアンスは改善を示すことができます。そうでない場合は、追加のトレーニングが必要になる可能性があります。
  - *高度なクエリ:* **ポリシーの実施:** たとえば、すべての外部メールリンクはスキャンされ、悪意のある場合はブロックされるというポリシーがあるとします。UrlClickEventsを使用して、悪意のあるリンクが実際にブロックとして表示されることを確認できます。たとえば、ThreatTypesに値があるのにActionTypeが「ClickAllowed」だった場合、システムは悪意のあるものと見なしたが、それでも許可した（通常はポリシーが上書き可能でない限り発生しないはず）ことを意味する可能性があります。そのシナリオを確認します。
    ```kql
    // 既知の悪意のあるリンクのクリックが許可されたかどうかを確認
    UrlClickEvents
    | where ThreatTypes contains "Malware" or ThreatTypes contains "Phish"
    | summarize AllowedCount=sumif(1, ActionType == "ClickAllowed"), Total=sum(1)
    ```
    ThreatTypesが悪意のあるコンテンツを示している場合（セーフリンクがブロックするため）、理想的にはAllowedCountは0であるべきです。ゼロでない場合、それは調査すべきセキュリティ制御のコンプライアンスギャップです。別のコンプライアンスの使用法：特定の部門が外部リンクを使用すべきではない場合、AccountUpnでフィルタリングできます（IdentityInfoと結合して部門を取得）して、たとえば、財務チームがリスクの高いリンクをクリックしたかどうかを確認し、追加の制御があることを確認します。コンプライアンスチームはその後、それらのグループに追加の制御またはトレーニングをターゲットにすることができます。
