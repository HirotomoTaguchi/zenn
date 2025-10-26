---
title: "DirectSendに関するメモ(TBA)"
emoji: "🛡" 
type: "tech" ## tech: 技術記事 / idea: アイデア記事
topics: [Security] 
published: true
---

Microsoft 365 の各テナントでは、**DirectSend (ダイレクトセンド)** という機能が有効になっていることがあり、有効であること自体がセキュリティリスクとなる可能性があります。まだ調査中の内容も含まれていますが、メモを残しています。

## DirectSendとは？

DirectSend は、オンプレミスのデバイス、アプリケーション、またはサードパーティのクラウドサービスから、Exchange Online 上のメールボックスへ（認証なしで）直接メールを送信するための方法です。この方法は、送信者ドメインが自組織のものである点を除けば、インターネットからの匿名の受信メールと似た動作となり、**認証を必要としません**。

### コマンド

PowerShell で以下のスクリプトを実行し、DirectSend がブロックされていることをテストします。（`To`, `From`, `SmtpServer` はご自身の環境に合わせて変更してください）

```powershell
$EmailMessage = @{
    To         = "XXX@yourdomain.com"
    From       = "YYY@yourdomain.com"
    Subject    = "DirectSend test"
    Body       = "Direct Send test"
    SmtpServer = "yourdomain-com.mail.protection.outlook.com" # MXレコードを確認
    Port       = "25"
    UseSSL     = $true
}
Send-MailMessage @EmailMessage
```

:::message alert
上記のコマンドを他組織に対して実施することはサイバー攻撃と同等の行為となりますので、テストする際には必ず許可された環境に対して実施してください。加えて、25番ポートはインターネットサービスプロバイダーやAzureなどのパブリッククラウドにおいて、デフォルトでブロックされていることがございます。
:::

## DirectSendの管理者がアwの設定

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


### DirectSendを利用せざるを得ない場合の対応

TBA


## まとめ


TBA
