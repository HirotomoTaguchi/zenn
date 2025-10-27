---
title: "Micorosoft 365 DirectSendに関するメモ(TBA)"
emoji: "🛡" 
type: "tech" ## tech: 技術記事 / idea: アイデア記事
topics: [Security] 
published: true
---

Microsoft 365 の各テナントでは、DirectSend という機能が有効になっていることがありますが、攻撃者による悪用も確認されており、メディア等でも対策の必要性が訴えられています ^[[Microsoft 365 'Direct Send' abused to send phishing as internal users](https://www.bleepingcomputer.com/news/security/microsoft-365-direct-send-abused-to-send-phishing-as-internal-users/)] 。まだ調査中の内容も含まれていますが、メモを残しています。

## DirectSendとは？

DirectSend は、オンプレミスのデバイス、アプリケーション、またはサードパーティのクラウドサービスから、Exchange Online 上のメールボックスへ（認証なしで）直接メールを送信するための方法です。

### DirectSendはなぜリスクがあるのか？

この方法は、送信者ドメインが自組織のものである点を除けば、インターネットからの匿名の受信メールと似た動作となり、**認証を必要としません**。加えて、DirectSendでは、SPF/DKIM/DMARCが失敗するにも関わらず、通信を内部通信として取り扱う竹、他のフィルタリングルールをバイパスしてユーザーに届いてしまう可能性が指摘されています。さらに、実行コマンドを後述していますが、メールアドレスとSmtpServerさえわかれば実行できるので、攻撃者が実行する難易度も低いという特徴があります。

:::message
実際にバイパスされてしまうかについては、環境やメールセキュリティ製品・設定によるのでご自身でご確認ください。
:::

### DirectSendはどのようなユースケースで必要なのか？

個人的にはあまり使ってほしくない機能ですが、プリンターからのメールや会議室の予約システムからのメールなどで使われていたりします。

### 実行コマンド

PowerShell で以下のスクリプトを実行し、DirectSend をテストできます。`To`, `From`, `SmtpServer` はご自身の環境に合わせて変更して利用します。尚、25番ポートはインターネットサービスプロバイダーやAzureなどのパブリッククラウドにおいて、デフォルトでブロックされていることがあるので、ご自宅で試そうと思ったあなたはかなり厳しいです。

```powershell
$EmailMessage = @{
    To         = "XXX@yourdomain.com"
    From       = "YYY@yourdomain.com"
    Subject    = "DirectSend test"
    Body       = "DirectSend test"
    SmtpServer = "yourdomain-com.mail.protection.outlook.com" # MXレコードを確認
    Port       = "25"
    UseSSL     = $true
}
Send-MailMessage @EmailMessage
```

:::message alert
上記のコマンドを他組織に対して実施することはサイバー攻撃と同等の行為となりますので、テストする際には必ず許可された環境に対して実施してください。
:::

## DirectSendの管理者が側の設定

### 前提条件

まず、Exchange Online PowerShell モジュールをインストールし、接続する必要があります。

1.  **モジュールのインストール (未実施の場合):**

```powershell
Install-Module -Name ExchangeOnlineManagement -Force
```

2.  **Exchange Online への接続:**

```powershell
Connect-ExchangeOnline
```

### 状態の確認

現在の設定状態を確認するには、以下のコマンドを実行します。

```powershell
Get-OrganizationConfig | Select-Object Identity, RejectDirectSend
```

**実行結果の例 (無効化されている場合):**
`RejectDirectSend` が `True` になっていれば、DirectSend はブロックされています。

### 無効化コマンド

接続後、以下のコマンドを実行して DirectSend をブロックします。

```powershell
Set-OrganizationConfig -RejectDirectSend $true
````

### （参考）DirectSendの有効化 (許可)

逆に DirectSend を許可（デフォルトの状態に戻す）場合は、以下のコマンドを実行します。

```powershell
Set-OrganizationConfig -RejectDirectSend $false
```

## DirectSendを利用せざるを得ない場合の対応

### DirectSend の利用の実態調査

DirectSendを無効にする前に、どれだけ使われているか見たいというケースがあると思います。どのように見れば一番スムーズに見ればいいのか苦心しており、ネットに転がっているクエリなどを使っても上手く拾ってくれないケースが多いのですが、少なくともAdvanced Huntingにおいて、M365の内部から内部へのメールは `{"DKIM":"none","DMARC":"none"}` となるのに対して、DirectSendは内部から内部でも `{"SPF":"fail","DKIM":"none","DMARC":"none","CompAuth":"fail"}` となることがわかりました。

![](https://github.com/user-attachments/assets/fc61393f-2c0c-4ae1-856d-f8312d477387)

他のも含まれてしまうかもしれませんが、以下のようなAdvanced Huntingで目付はできるかと思いました。

```
EmailEvents 
| where Timestamp > ago(30d) 
| where SenderFromDomain contains "yourdomain.com"
| where RecipientDomain contains "yourdomain.com"
| extend AuthDetails = todynamic(AuthenticationDetails)
| where AuthDetails.SPF == "fail" 
    and AuthDetails.DKIM == "none" 
    and AuthDetails.DMARC == "none" 
    and AuthDetails.CompAuth == "fail"
```

### DirectSend を限定的に許可する

TBA（調査中）

https://techcommunity.microsoft.com/blog/exchange/direct-send-vs-sending-directly-to-an-exchange-online-tenant/4439865

## まとめ

TBA（調査中）
