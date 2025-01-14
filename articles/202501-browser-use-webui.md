---
title: "Browser-UseのImportError:cannot import name AgentStepErrorTelemetryEvent"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [Browser-Use WebUI, Browser-Use] 
published: true
---

## 概要

Browser-Use WebUI を Windows 環境で実行しようとした際に、次のエラーが発生する件に関する解決策を記します。

エラー文:

```
ImportError: cannot import name 'AgentStepErrorTelemetryEvent' from 'browser_use.telemetry.views'
```

## 発生背景

この問題は、Browser-Use WebUI のリポジトリのソースコード内で使用されているモジュール、`browser_use.telemetry.views` が最新バージョンのインターフェースと一致していないことが原因です。

## 暫定対処

下記の通り、`browser-use` パッケージの指定したバージョンを再インストールすることで問題が解決しました。

   実施したコマンド:
   ```bash
   uv pip install browser-use==0.1.18
   ```

## 環境のセットアップ

### 必要な前提条件

- Python 3.11以上（私は 3.12.8 を利用）
- uv
- Windows 11（でしか試してません）

### 手順
1. **リポジトリのクローン／ダウンロード**
フォルダを作成し、リポジトリのクローン／ダウンロードします。
   ```bash
   git clone https://github.com/browser-use/web-ui.git . 
   ```

2. **仮想環境の作成**

   ```bash
   uv venv --python 3.12
   ```

   
   ```bash
   .venv\Scripts\activate 
   ```

   LinuxやMacでは `source .venv/bin/activate` を使用します。

3. **必要なパッケージのインストール**

   ```bash
   uv pip install browser-use==0.1.18
   ```
   
   ```bash
   playwright install
   ```

   ```bash
   uv pip install -r requirements.txt
   ```
   
4. **環境変数の設定**

   `.env` ファイルを作成し、必要なAPIキーやブラウザパスを設定します。

5. **起動**

   ```bash
   python webui.py --ip 127.0.0.1 --port 7788
   ```

   ブラウザから `http://127.0.0.1:7788` へアクセスし、ツールが起動することを確認します。

## 再実行で正常動作を確認

上記の階段を完了後に、WebUI が正常に動作することを確認しました。

## おわりに

Browser-Use WebUI の試用中に発生した問題は、パッケージのバージョンコンフリクトで解決することができました。誰かの参考になれば幸いです。

https://github.com/browser-use/web-ui/issues/102
