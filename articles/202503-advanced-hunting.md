---
title: "Advanced Hunting のユースケースをメモってく（WIP）"
emoji: "🛡" 
type: "tech" ## tech: 技術記事 / idea: アイデア記事
topics: [Microsoft Defender] 
published: false
published_at: 2025-03-15
---

Advanced Hunting のユースケースをメモってく（WIP）

## アラートと動作

### AlertEvidence

-   概要
    -   `AlertEvidence` テーブルには、Defender のアラートをトリガーしたイベントに関するエンティティ（ファイル、IPアドレス、ユーザー、デバイスなど）の情報が保存されています。アラートをキーに様々な情報を確認できるので、インシデントレスポンスや定期的な振り返りなどのユースケースで活用できます。
-   ユースケース
    -   特定のアラート（AlertIdまたはTitle別）のエビデンスエンティティを取得します。これにより、さらなる分析のために、その警告に関与するすべてのファイル、IPを表示します。ここでは、アラートのタイトルをベースに検索を行います。
        ```kql
        // 特定のアラートのエビデンスエンティティを取得
        AlertEvidence
        | where Title == "Suspicious PowerShell Behavior"
        | project Timestamp, EntityType, EvidenceRole, FileName, SHA1, AccountName, DeviceName
        ```

### AlertInfo

-   概要
    -   `AlertInfo` テーブルには、Defenderで発生したアラート自体の詳細情報（重大度、ステータス、分類、関連インシデントなど）が格納されています。インシデントに含まれるアラートの全体像を把握したり、特定の種類のアラートを調査したりする際に役立ちます。
-   ユースケース
    -   特定のインシデントIDに関連するすべてのアラート情報を取得し、インシデントの全体像を把握します。
        ```kql
        // 特定のインシデントに関連するアラートを取得
        AlertInfo
        | where IncidentId == 12345 // 調査したいインシデントIDを指定
        | project Timestamp, AlertId, Title, Severity, Category, Status, ServiceSource, DetectionSource
        ```

### BehaviorEntities

-   概要
    -   `BehaviorEntities` テーブルには、アラートやインシデントに関連付けられたエンティティ（デバイス、ユーザー、メールボックスなど）に関する情報が格納されています。特定の振る舞い(Behavior)にどのエンティティが関与したかを調査する際に使用します。
-   ユースケース
    -   特定の振る舞いID（BehaviorId）に関連するエンティティ（デバイスやユーザー）を特定します。
        ```kql
        // 特定の振る舞いに関連するエンティティを特定
        BehaviorEntities
        | where BehaviorId == "abcdef12345" // 調査したい振る舞いIDを指定
        | project BehaviorId, EntityType, EntityValue, Role
        ```

### BehaviorInfo

-   概要
    -   `BehaviorInfo` テーブルには、アラートやインシデントで検出された悪意のある、または疑わしい振る舞い（MITRE ATT&CKの戦術やテクニックなど）に関する詳細情報が格納されています。どのような攻撃手法が検知されたかを分析するのに役立ちます。
-   ユースケース
    -   組織内で検出された MITRE ATT&CK のテクニックを頻度順に表示し、最もよく見られる攻撃手法を把握します。
        ```kql
        // 検出されたMITRE ATT&CKテクニックを集計
        BehaviorInfo
        | where isnotempty(AttackTechniques)
        | mv-expand AttackTechniques
        | summarize count() by tostring(AttackTechniques)
        | sort by count_ desc
        ```

## アプリと ID

### AADSignInEventsBeta

-   概要
    -   `AADSignInEventsBeta` テーブルには、Azure Active Directory (Azure AD) のユーザーサインインイベントに関する詳細情報が格納されています（ベータ版スキーマ）。サインインの試行（成功・失敗）、場所、デバイス、条件付きアクセスポリシーなどの情報を分析できます。
-   ユースケース
    -   失敗したサインインイベントを調査し、異常な場所からのアクセスやブルートフォース攻撃の兆候がないか確認します。
        ```kql
        // 過去24時間の失敗したサインインイベントを取得
        AADSignInEventsBeta
        | where Timestamp > ago(1d)
        | where ErrorCode != 0 // ErrorCode 0 は成功を示す
        | project Timestamp, UserPrincipalName, AppDisplayName, IPAddress, Location, DeviceDetail, ConditionalAccessStatus, ErrorCode, FailureReason
        | sort by Timestamp desc
        ```

### AADSpnSignInEventsBeta

-   概要
    -   `AADSpnSignInEventsBeta` テーブルには、Azure Active Directory (Azure AD) のサービスプリンシパルおよびマネージドIDによるサインインイベントに関する情報が格納されています（ベータ版スキーマ）。アプリケーションやサービスによるリソースアクセスを追跡するのに役立ちます。
-   ユースケース
    -   特定のサービスプリンシパルによるサインインアクティビティを監視し、予期しないアクセスや失敗がないか確認します。
        ```kql
        // 特定のサービスプリンシパルによるサインインイベントを調査
        AADSpnSignInEventsBeta
        | where Timestamp > ago(7d)
        | where ServicePrincipalId == "00000000-0000-0000-0000-000000000000" // 調査対象のSPN IDを指定
        | project Timestamp, ServicePrincipalName, ResourceDisplayName, IPAddress, Location, ConditionalAccessStatus, ErrorCode, FailureReason
        | sort by Timestamp desc
        ```

### CloudAppEvents

-   概要
    -   `CloudAppEvents` テーブルには、Microsoft Defender for Cloud Apps によって監視されているクラウドアプリケーション（Microsoft 365, Salesforce, Boxなど）のアクティビティログが格納されています。ファイル操作、アクセス許可の変更、ユーザーアクティビティなどを追跡できます。
-   ユースケース
    -   SharePoint Onlineで外部ユーザーと共有されたファイルを特定し、意図しない情報共有がないか確認します。
        ```kql
        // SharePoint Onlineでの外部共有イベントを検出
        CloudAppEvents
        | where Timestamp > ago(7d)
        | where Application == "Microsoft SharePoint Online"
        | where ActionType == "FileShared"
        | extend SharingType = extractjson("$.SharingType", RawEventData, typeof(string))
        | where SharingType == "External" // または "AnyoneWithLink" など、調査対象に応じて変更
        | project Timestamp, AccountDisplayName, FileName, SiteUrl, IPAddress, UserAgent
        ```

### IdentityInfo

-   概要
    -   `IdentityInfo` テーブルには、Microsoft Defender for Identity やその他のソースから収集されたユーザーアカウントに関する情報（SID、表示名、メールアドレス、リスクレベルなど）が格納されています。ユーザーエンティティに関する属性情報を集約して提供します。
-   ユースケース
    -   Microsoft Defender for Identity によってリスクが高いと評価されたユーザーアカウントを特定し、その活動状況を他のテーブルと関連付けて調査します。
        ```kql
        // 高リスクと判定されたユーザーを特定
        IdentityInfo
        | where InvestigationPriority > 50 // リスクスコアの閾値は環境に応じて調整
        | project AccountUpn, AccountDisplayName, RiskScore, InvestigationPriority
        | sort by InvestigationPriority desc
        ```

### IdentityLogonEvents

-   概要
    -   `IdentityLogonEvents` テーブルには、オンプレミスの Active Directory 環境における認証イベント（NTLM、Kerberos、RDPなど）に関する情報が格納されます。主に Microsoft Defender for Identity によって収集されます。
-   ユースケース
    -   特定のサーバーに対するNTLM認証の成功イベントを調査し、不審なアカウントによるアクセスがないか確認します。
        ```kql
        // 特定サーバーへのNTLMログオン成功イベントを調査
        IdentityLogonEvents
        | where Timestamp > ago(1d)
        | where ActionType == "LogonSuccess"
        | where LogonType == "Network" // NTLM認証を示すことが多い
        | where Protocol == "Ntlm"
        | where TargetDeviceName == "TargetServerName.contoso.local" // 調査対象サーバー名を指定
        | project Timestamp, AccountUpn, DeviceName, IPAddress, LogonType, Protocol
        ```

### OAuthAppInfo
-   概要
    -   `OAuthAppInfo` テーブルには、組織のAzure AD環境に登録されているOAuthアプリケーションに関する情報（アプリ名、発行元、アクセス許可、リスクレベルなど）が格納されています。OAuthアプリの管理とリスク評価に役立ちます。
-      ユースケース
    -   リスクの高いOAuthアプリ（高権限、未検証の発行元など）を発見する。^[[Microsoft 365 環境におけるOAuthアプリのリスクと対策](https://zenn.dev/hirotomotaguchi/articles/202504_m365-oauth-security##oauth-%E3%82%A2%E3%83%97%E3%83%AA%E3%81%AE%E8%A6%8B%E3%81%88%E3%82%8B%E5%8C%96%E3%81%A8%E5%80%8B%E5%88%A5%E3%81%AE%E5%88%B6%E5%BE%A1)]
        ```kql
        // リスクの高いOAuthアプリを発見
        OAuthAppInfo
        | where AppStatus == "Enabled" // 有効なアプリのみ対象
        | where PrivilegeLevel == "High" // 高権限を持つアプリ
        | where IsVerifiedPublisher != true and Publisher == "{}" // 未検証の発行元
        | project AppName, Publisher, PrivilegeLevel, PermissionCount, AppOrigin, FirstSeen, LastSeen
        ```

## メールとコラボレーション

### EmailAttachmentInfo

-   概要
    -   `EmailAttachmentInfo` テーブルには、Exchange Online を通過したメールに含まれる添付ファイルに関する詳細情報（ファイル名、ハッシュ値、サイズ、マルウェア判定結果など）が格納されています。
-   ユースケース
    -   特定のハッシュ値を持つ添付ファイルを含むメールを特定し、受信者や送信者、配信状況を調査します。
        ```kql
        // 特定のハッシュを持つ添付ファイルを含むメールを検索
        EmailAttachmentInfo
        | where SHA256 == "特定のファイルハッシュ値"
        | project FileName, FileType, MalwareFilterVerdict, SenderFromAddress, RecipientEmailAddress, NetworkMessageId, Timestamp
        | join kind=inner EmailEvents on NetworkMessageId
        | project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, FileName, FileType, ThreatTypes, DetectionMethods
        ```

### EmailEvents

-   概要
    -   `EmailEvents` テーブルには、Exchange Online を通過したメールのイベントログ（送受信、配信、スパム/マルウェア判定、フィッシング判定、ZAPなど）が保存されています。Defender for Office 365 の判定結果を含む、メールフロー全体の分析が可能です。
-   ユースケース
    -   Microsoft Defender for Office 365 (MDO) のAIによって脅威（マルウェア、フィッシングなど）があると判定されたメールの傾向を分類別に可視化します。
        ```kql
        // MDOが脅威と判定したメールの分類別件数を表示
        EmailEvents
        | where Timestamp > ago(7d)
        | where ThreatTypes != "" // 何らかの脅威が検出されたメール
        | summarize Count = dcount(NetworkMessageId) by ThreatTypes
        | sort by Count desc
        | render columnchart
        ```

### EmailPostDeliveryEvents

-   概要
    -   `EmailPostDeliveryEvents` テーブルには、メールが受信者のメールボックスに配信された後に発生したアクション（Zero-hour auto purge (ZAP) による削除、ユーザーによるフィッシング報告、動的配信による添付ファイルのスキャン完了など）に関する情報が格納されています。
-   ユースケース
    -   ZAP (Zero-hour auto purge) によって、配信後に脅威と判定されて自動的に削除または隔離されたメールを確認します。
        ```kql
        // ZAPによって処理されたメールを確認
        EmailPostDeliveryEvents
        | where Timestamp > ago(1d)
        | where ActionType == "ZAP" // ZAPアクションのみフィルタ
        | project Timestamp, NetworkMessageId, Subject, SenderFromAddress, RecipientEmailAddress, OriginalDeliveryFolder, FinalDeliveryFolder, ActionResult
        ```

### EmailUrlInfo

-   概要
    -   `EmailUrlInfo` テーブルには、メール本文や添付ファイル内に含まれるURLに関する情報（URL自体、脅威判定結果など）が格納されています。
-   ユースケース
    -   悪意のある（Malware, Phish）と判定されたURLを含むメールを特定し、受信者やメールの件名などを確認します。
        ```kql
        // 悪意のあるURLを含むメールを検索
        EmailUrlInfo
        | where ThreatTypes has_any ("Malware", "Phish")
        | project Url, NetworkMessageId
        | join kind=inner EmailEvents on NetworkMessageId
        | project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, Url, ThreatTypes
        | distinct NetworkMessageId, Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, Url, ThreatTypes // 重複削除
        ```

### UrlClickEvents

-   概要
    -   `UrlClickEvents` テーブルには、Microsoft Defender for Office 365 のセーフリンク機能によって保護されたURL（メール、Teamsメッセージ内など）のクリックイベントに関する情報が格納されます。
-   ユースケース
    -   セーフリンクによってブロックされた、または警告が表示された悪意のあるURLをクリックしたユーザーを特定します。
        ```kql
        // セーフリンクでブロック/警告されたURLクリックを調査
        UrlClickEvents
        | where Timestamp > ago(1d)
        | where ActionType in ("ClickBlocked", "ClickAllowed", "BlockPage") // 必要に応じてActionTypeを調整
        | where ThreatTypes has_any ("Malware", "Phish") // 悪意のあると判定されたURL
        | project Timestamp, Url, AccountUpn, Workload, ActionType, ThreatTypes, NetworkMessageId, IPAddress, Location
        ```

## デバイス

### DeviceEvents

-   概要
    -   `DeviceEvents` テーブルには、Microsoft Defender for Endpoint によって収集されたデバイス上の様々なセキュリティ関連イベント（ウイルス対策の検出・ブロック、Exploit Guard のイベント、攻撃表面の縮小(ASR)ルール発動、ネットワーク保護イベントなど）が格納されています。
-   ユースケース
    -   攻撃表面の縮小(ASR)ルールが発動したイベントを調査し、どのようなルールが、どのプロセスに対して、どのデバイスでトリガーされたかを確認します。
        ```kql
        // ASRルール発動イベントを調査
        DeviceEvents
        | where Timestamp > ago(7d)
        | where ActionType startswith "Asr" // ASR関連のアクションタイプ
        | project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
        | sort by Timestamp desc
        ```

### DeviceFileCertificateInfo

-   概要
    -   `DeviceFileCertificateInfo` テーブルには、デバイス上のファイルのデジタル署名証明書に関する情報（発行者、拇印、有効期限、署名状態など）が格納されています。ファイルの信頼性を評価する際に役立ちます。
-   ユースケース
    -   信頼されていない発行元によって署名された実行ファイル（.exe, .dllなど）を特定します。
        ```kql
        // 信頼されていない発行元によって署名された実行ファイルを検索
        DeviceFileCertificateInfo
        | where IsTrusted == false
        | project CertificateIssuer, CertificateSubject, CertificateThumbprint, Signer, DeviceId
        | join kind=inner (
            DeviceFileEvents
            | where FileName endswith ".exe" or FileName endswith ".dll"
            | distinct SHA1, InitiatingProcessFileName, DeviceId // ファイルイベントから実行ファイル情報取得
        ) on DeviceId
        | project Timestamp=now(), InitiatingProcessFileName, Signer, CertificateIssuer, CertificateSubject, CertificateThumbprint // DeviceIdは含めない場合もある
        ```
        *注: このクエリは例であり、`DeviceFileCertificateInfo`と`DeviceFileEvents`の直接的な関連付けはSHA1などを介して行う方が正確な場合があります。*

### DeviceFileEvents

-   概要
    -   `DeviceFileEvents` テーブルには、デバイス上でのファイルの作成、変更、削除、名前変更といったファイルシステム関連のアクティビティが記録されています。マルウェアの活動追跡や情報漏洩の調査などに使用できます。
-   ユースケース
    -   特定のファイルハッシュ（既知のマルウェアなど）を持つファイルが作成された、または変更されたイベントを調査します。
        ```kql
        // 特定のハッシュを持つファイルのイベントを調査
        let hashList = datatable(SHA256: string)
        [
            "XXX", // XXXに調査したいハッシュを入れる
            "YYY",
            "ZZZ"
        ];
        DeviceFileEvents
        | where Timestamp > ago(7d)
        | where SHA256 in (hashList) or SHA1 in (hashList) or MD5 in (hashList) // 対応するハッシュタイプで検索
        | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
        ```

### DeviceImageLoadEvents

-   概要
    -   `DeviceImageLoadEvents` テーブルには、プロセスがDLL（ダイナミックリンクライブラリ）や実行可能イメージを読み込んだ際のイベント情報が格納されています。DLLインジェクションや特定のライブラリを使用するマルウェアの調査に役立ちます。
-   ユースケース
    -   特定の不審なDLL（例: 未署名のDLL）が読み込まれているプロセスを調査します。
        ```kql
        // 未署名のDLLの読み込みイベントを調査
        DeviceImageLoadEvents
        | where Timestamp > ago(1d)
        | where IsSigned == false
        | where FileName endswith ".dll"
        | project Timestamp, DeviceName, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessId
        ```

### DeviceInfo

-   概要
    -   `DeviceInfo` テーブルには、Microsoft Defender for Endpoint にオンボードされているデバイスのインベントリ情報（OSバージョン、IPアドレス、MACアドレス、ログオンユーザー、正常性状態、リスクレベルなど）が格納されています。デバイスの状態管理やインシデント対応時の情報収集に不可欠です。
-   ユースケース
    -   特定のOSバージョン（例: サポート終了間近のWindowsバージョン）を実行しているデバイスを特定し、アップデート計画に役立てます。
        ```kql
        // 特定のOSバージョンを実行しているデバイスを検索
        DeviceInfo
        | where OSVersion startswith "10.0.19041" // 例: Windows 10 2004
        | project DeviceName, OSPlatform, OSVersion, PublicIP, LastSeen, HealthStatus, RiskScore
        ```

### DeviceLogonEvents

-   概要
    -   `DeviceLogonEvents` テーブルには、デバイスへのユーザーログオンイベント（インタラクティブ、リモート、ネットワークログオンなど）に関する情報が格納されています。不正アクセスや横展開の試みを調査する際に重要です。
-   ユースケース
    -   特定のデバイスに対するリモートデスクトップ(RDP)でのログオン成功イベントを調査します。
        ```kql
        // 特定デバイスへのRDPログオン成功イベントを調査
        DeviceLogonEvents
        | where Timestamp > ago(7d)
        | where ActionType == "LogonSuccess"
        | where LogonType == "RemoteInteractive" // RDPログオンを示す
        | where DeviceName == "TargetDeviceName" // 調査対象デバイス名を指定
        | project Timestamp, DeviceName, AccountUpn, AccountDomain, LogonType, RemoteIP, RemoteDeviceName
        ```

### DeviceNetworkEvents

-   概要
    -   `DeviceNetworkEvents` テーブルには、デバイスが行ったネットワーク接続や通信（TCP/UDP接続確立、DNSクエリ、リスニングポートなど）に関する情報が格納されています。マルウェアのC&C通信や不正なデータ送信の検出に役立ちます。
-   ユースケース
    -   既知のRMM（Remote Management and Monitoring）ツールのリストに含まれるドメインへのネットワーク通信を検出します。（提供済みのクエリ例）
        ```kql
        // RMMツールの通信を検出
        // let SanctionRMM = dynamic("bomgarcloud.com"); // E.g Approved RMM - whitelisting
        let RMMList=externaldata(URI: string, RMMTool: string)
            [h'https://raw.githubusercontent.com/jischell-msft/RemoteManagementMonitoringTools/refs/heads/main/Network%20Indicators/RMM_SummaryNetworkURI.csv'];
        let RMMUrl =
            RMMList
            | project URI;
        DeviceNetworkEvents
        | where Timestamp > ago(1h)
        | where RemoteUrl has_any (RMMUrl) // URIカラム名をRemoteUrlに合わせる想定
        // | where not (RemoteUrl has_any (SanctionRMM)) // 承認済みを除外する場合
        | summarize arg_max(Timestamp, *) by DeviceId
        | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName
        ```
    -   （別ユースケース）既知の悪意のあるIPアドレスリストへの通信を検出する。
        ```kql
        // 悪意のあるIPへの通信を検出
        let MaliciousIPs = external_data(IPAddress: string) // 悪意のあるIPリストの場所を指定
        [
            h@"https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt" // 例: ipsumリスト
        ]
        | project IPAddress;
        DeviceNetworkEvents
        | where Timestamp > ago(1d)
        | where RemoteIP in (MaliciousIPs)
        | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
        ```

### DeviceNetworkInfo

-   概要
    -   `DeviceNetworkInfo` テーブルには、デバイスのネットワークアダプターに関する情報（MACアドレス、IPアドレス、DHCPサーバー、DNSサーバーなど）が格納されています。ネットワーク構成の確認や、特定のネットワークセグメントに属するデバイスの特定に役立ちます。
-   ユースケース
    -   特定のIPアドレス範囲に属するデバイスのリストを取得します。
        ```kql
        // 特定のIPアドレス範囲に属するデバイスを取得
        DeviceNetworkInfo
        | where IPAddresses has "192.168.1." // 調査したいIP範囲やサブネットを指定
        | project DeviceName, MacAddress, IPAddresses, ConnectedNetworks, DhcpServer, DnsAddresses
        ```

### DeviceProcessEvents

-   概要
    -   `DeviceProcessEvents` テーブルには、デバイス上でのプロセス作成イベントに関する詳細情報（プロセス名、コマンドライン引数、作成元プロセス、実行ユーザーなど）が格納されています。マルウェアの実行、不正なスクリプトの活動、横展開などを調査する上で中心的なテーブルです。
-   ユースケース
    -   PowerShell を使用してエンコードされたコマンドを実行しているプロセスを検出します。これはしばしばファイルレスマルウェアや攻撃者によって悪用されます。
        ```kql
        // エンコードされたPowerShellコマンドの実行を検出
        DeviceProcessEvents
        | where Timestamp > ago(1d)
        | where InitiatingProcessFileName =~ "powershell.exe" or ProcessCommandLine has "powershell"
        | where ProcessCommandLine has_any ("-encodedcommand", "-enc", "-e")
        | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
        | sort by Timestamp desc
        ```

### DeviceRegistryEvents

-   概要
    -   `DeviceRegistryEvents` テーブルには、デバイス上のレジストリキーや値の作成、変更、削除に関するイベント情報が格納されています。マルウェアによる永続化設定、構成変更、機密情報へのアクセス試行などを検出するのに役立ちます。
-   ユースケース
    -   Windows の Run キー（`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` など）への書き込みイベントを監視し、マルウェアによる永続化の試みを検出します。
        ```kql
        // Runキーへの書き込みイベントを監視
        DeviceRegistryEvents
        | where Timestamp > ago(7d)
        | where ActionType == "RegistryValueSet" or ActionType == "RegistryKeyCreated"
        | where RegistryKey contains @"\Software\Microsoft\Windows\CurrentVersion\Run"
        | project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
        ```

## Defender 脆弱性の管理

### DeviceTvmInfoGathering

-   概要
    -   `DeviceTvmInfoGathering` テーブルには、Defender 脆弱性管理 (TVM) がデバイスから脆弱性評価のための情報（OS、アプリケーション、構成など）を収集した際のイベントとそのステータスが記録されます。TVM機能の健全性を監視するのに役立ちます。
-   ユースケース
    -   過去24時間で脆弱性情報の収集に失敗したデバイスを特定します。
        ```kql
        // 脆弱性情報収集に失敗したデバイスを特定
        DeviceTvmInfoGathering
        | where Timestamp > ago(1d)
        | where Status != "Success" // 成功以外のステータス
        | summarize arg_max(Timestamp, *) by DeviceId // 各デバイスの最新の失敗イベント
        | project Timestamp, DeviceName, Status, AdditionalFields // AdditionalFieldsに失敗理由が含まれる場合がある
        ```

### DeviceTvmInfoGatheringKB

-   概要
    -   `DeviceTvmInfoGatheringKB` テーブルには、Defender 脆弱性管理の情報収集プロセスで参照された構成や設定項目（ナレッジベース、KB）に関する情報が格納されています。特定の構成項目がどのように評価されているかを追跡できます。
-   ユースケース
    -   特定の構成項目（例: SMBv1が無効になっているか）に関する情報収集が行われたデバイスを特定します。
        ```kql
        // 特定の構成項目に関する情報収集イベントを検索
        DeviceTvmInfoGatheringKB
        | where ConfigurationId == "scid-1001" // 例: SMBv1 Server に関する構成ID (実際のIDを確認要)
        | project Timestamp, DeviceId, ConfigurationId, ConfigurationCategory, ConfigurationSubcategory, Status
        | join kind=inner DeviceInfo on DeviceId
        | project Timestamp, DeviceName, ConfigurationId, ConfigurationCategory, Status
        ```

### DeviceTvmSecureConfigurationAssessment

-   概要
    -   `DeviceTvmSecureConfigurationAssessment` テーブルには、Defender 脆弱性管理によるデバイスのセキュリティ構成評価の結果が格納されます。OSやアプリケーションの推奨されるセキュリティ設定と比較し、準拠状況を評価します。
-   ユースケース
    -   特定のセキュリティ構成（例: パスワードポリシー）が推奨設定に準拠していないデバイスを特定します。
        ```kql
        // 特定の構成が非準拠(Misconfigured)のデバイスを検索
        DeviceTvmSecureConfigurationAssessment
        | where IsCompliant == false // または IsApplicable == true and IsCompliant == false
        | where ConfigurationId == "scid-2010" // 例: パスワードの最低文字数に関する構成ID (実際のIDを確認要)
        | summarize arg_max(Timestamp, *) by DeviceId, ConfigurationId
        | project Timestamp, DeviceName, ConfigurationId, ConfigurationName, ConfigurationCategory, OSPlatform, OSVersion, IsCompliant
        ```

### DeviceTvmSecureConfigurationAssessmentKB

-   概要
    -   `DeviceTvmSecureConfigurationAssessmentKB` テーブルには、セキュリティ構成評価に関連するナレッジベース（KB）情報と、その評価結果（準拠/非準拠）が格納されています。評価の根拠となる詳細情報を提供します。
-   ユースケース
    -   特定のセキュリティ勧告（例: 特定のCISベンチマーク項目）に関連する構成評価の結果を確認します。
        ```kql
        // 特定のKBに関連する構成評価の結果を確認
        DeviceTvmSecureConfigurationAssessmentKB
        | where CveId == "" and ReferenceUri contains "cisecurity.org" // 例: CISベンチマーク関連 (特定のKBがあればそれを指定)
        | project Timestamp, DeviceId, ConfigurationId, Finding, ConfigurationCategory, Status
        | join kind=inner DeviceInfo on DeviceId
        | project Timestamp, DeviceName, ConfigurationId, Finding, ConfigurationCategory, Status
        ```
        *注: このテーブルは主に内部的な関連付けに使われることが多く、直接クエリする機会は少ないかもしれません。*

### DeviceTvmSoftwareEvidenceBeta

-   概要
    -   `DeviceTvmSoftwareEvidenceBeta` テーブルには、デバイス上のソフトウェアインベントリ情報の根拠となるデータ（検出されたファイルパス、レジストリキー、バージョン情報など）が格納されています（ベータ版スキーマ）。ソフトウェアがどのように検出・識別されたかの詳細を提供します。
-   ユースケース
    -   特定のソフトウェア（例: 7-Zip）がデバイス上でどのように検出されたかの証拠（ファイルパスなど）を確認します。
        ```kql
        // 特定ソフトウェアの検出根拠を確認
        DeviceTvmSoftwareEvidenceBeta
        | where SoftwareName == "7-Zip"
        | project DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, EvidenceType, EvidenceLocation, EvidenceValue
        | join kind=inner DeviceInfo on DeviceId
        | project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, EvidenceType, EvidenceLocation, EvidenceValue
        ```

### DeviceTvmSoftwareInventory

-   概要
    -   `DeviceTvmSoftwareInventory` テーブルには、Defender 脆弱性管理によって収集されたデバイス上のソフトウェアインベントリ情報（ソフトウェア名、ベンダー、バージョン、インストールパス、EoL情報など）が格納されています。ソフトウェア資産管理や脆弱性管理の基礎となります。
-   ユースケース
    -   サポート終了(End of Life - EoL)を迎えている、または間近なソフトウェアがインストールされているデバイスを特定します。
        ```kql
        // サポート終了(EoL)または間近なソフトウェアを検索
        DeviceTvmSoftwareInventory
        | where EndOfSupportStatus == "Reached" or EndOfSupportStatus == "Approaching" // EoL状態を指定
        | project DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate
        | join kind=inner DeviceInfo on DeviceId
        | project DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate
        ```

### DeviceTvmSoftwareVulnerabilities

-   概要
    -   `DeviceTvmSoftwareVulnerabilities` テーブルには、デバイス上のソフトウェアに存在する既知の脆弱性（CVE）に関する情報（CVE ID、深刻度(CVSSスコア)、公開日、パッチ情報など）が格納されています。優先的に対応すべき脆弱性を特定するのに不可欠です。
-   ユースケース
    -   深刻度が「クリティカル(Critical)」または「重要(High)」な脆弱性を持つソフトウェアがインストールされているデバイスを特定し、関連するCVE情報と共に表示します。
        ```kql
        // クリティカルまたは重要な脆弱性を持つデバイスを検索
        DeviceTvmSoftwareVulnerabilities
        | where CvssScore >= 7.0 // CVSS v3スコアが7.0以上 (High or Critical)
        | summarize arg_max(Timestamp, *) by DeviceId, CveId // 各デバイス、各CVEの最新情報を取得
        | project DeviceId, CveId, VulnerabilitySeverityLevel, CvssScore, SoftwareVendor, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate, RecommendedSecurityUpdateId
        | join kind=inner DeviceInfo on DeviceId
        | project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, CvssScore, SoftwareVendor, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate
        ```

### DeviceTvmSoftwareVulnerabilitiesKB

-   概要
    -   `DeviceTvmSoftwareVulnerabilitiesKB` テーブルには、ソフトウェアの脆弱性に関連するナレッジベース（KB）情報（脆弱性の詳細説明、関連リンクなど）と脆弱性情報（CVE ID）が関連付けられています。脆弱性の背景情報を得るのに役立ちます。
-   ユースケース
    -   特定のCVE番号（例: Log4ShellのCVE-2021-44228）に関連する脆弱性情報を持つデバイスと、その脆弱性に関する詳細情報を表示します。
        ```kql
        // 特定のCVEに関連する脆弱性を持つデバイスとKB情報を表示
        DeviceTvmSoftwareVulnerabilitiesKB
        | where CveId == "CVE-2021-44228" // 調査したいCVE IDを指定
        | project CveId, VulnerabilityDescription, VulnerabilitySeverityLevel, CvssScore, VulnerabilityUrls
        | join kind=inner (
            DeviceTvmSoftwareVulnerabilities
            | where CveId == "CVE-2021-44228"
            | summarize arg_max(Timestamp, *) by DeviceId, CveId
            | project DeviceId, CveId, SoftwareName, SoftwareVersion
        ) on CveId
        | join kind=inner DeviceInfo on DeviceId
        | project DeviceName, CveId, SoftwareName, SoftwareVersion, VulnerabilitySeverityLevel, CvssScore, VulnerabilityDescription, VulnerabilityUrls
        ```

## 露出管理

### ExposureGraphEdges

-   概要
    -   `ExposureGraphEdges` テーブルには、Microsoft Defender 露出管理 (Defender EASM) によって構築された攻撃経路グラフにおけるエンティティ（ノード）間の関連性（エッジ）が示されます。ノード間の関係性（例：「実行する」、「接続する」、「脆弱性を持つ」など）を表現します。
-   ユースケース
    -   特定の重要な資産（例：機密データを持つサーバー `TargetAssetNodeId`）に到達可能な他の資産（ノード）との関係性を調査します。
        ```kql
        // 特定の資産への接続経路(エッジ)を調査
        ExposureGraphEdges
        | where TargetNodeId == "TargetAssetNodeId" // 対象資産のノードIDを指定
        | project SourceNodeId, EdgeLabel, TargetNodeId
        | join kind=inner ExposureGraphNodes on $left.SourceNodeId == $right.NodeId
        | project SourceNodeName=NodeName, SourceNodeType=NodeLabel, EdgeLabel, TargetNodeId
        ```
        *注: 実際のノードIDやラベルは環境によって異なります。*

### ExposureGraphNodes

-   概要
    -   `ExposureGraphNodes` テーブルには、Microsoft Defender 露出管理 (Defender EASM) によって構築された攻撃経路グラフのノード（デバイス、ユーザー、脆弱性、ソフトウェア、ネットワークインターフェースなどのエンティティ）の情報が格納されています。
-   ユースケース
    -   組織内で「公開(Public facing)」として識別されている資産（ノード）を特定します。
        ```kql
        // 公開されている資産(ノード)を特定
        ExposureGraphNodes
        | where NodeAttributes has "Public facing" // 公開属性を持つノード (属性名は要確認)
        | project NodeId, NodeName, NodeLabel, NodeAttributes
        ```
