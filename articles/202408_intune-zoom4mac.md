---
title: "Intune を利用して、macOSにZoomを配信してみた"
emoji: "💻" 
type: "tech" # tech: 技術記事 / idea: アイデア記事
topics: [Zoom, Intune] 
published: false
---

## アプリの配信
- [Zoom のサポートページ](https://support.zoom.com/hc/ja/article?id=zm_kb&sysparm_article=KB0060418#collapseMac)から ZoomInstallerIT.pkg ファイルをダウンロードする。
- Intune でpkgファイルを指定して配布する。

## 【任意】　アプリの制限
- 以下のような plist を作成する。
- 名前は任意であるが us.zoom.config.plist としておくとわかりやすい。
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>nogoogle</key>
    <true/>
    <key>nofacebook</key>
    <true/>
    <key>PackageRecommend</key>
    <dict>
        <key>ZAutoFullScreenWhenViewShare</key>
        <true/>
        <key>EnableSilentAutoUpdate</key>
        <true/>
    </dict>
    <key>zDisableFT</key>
    <true/>
</dict>
</plist>
```
