# opm_hdcp_force

Windows 標準の OPM (Output Protection Manager) API だけを使って、HDCP を常時有効にするツール。
DRM コンテンツを再生しなくても HDCP を ON にでき、落ちたときは自動で復帰させる。

> **検証用・研究目的のツールです。** OPM のドライバ証明書チェーンの検証は意図的に省略しています。
> DRM 準拠クライアントとしては使えません。自分の管理する検証機でのみ実行してください。

## 動作環境

- 動作確認: Intel 内蔵 GPU / Windows 11
- HDCP に対応したディスプレイ出力（GPU ドライバが OPM に対応していること）

## 入手・ビルド

### ビルド済みの exe を使う

[Releases](../../releases) から `opm_hdcp_force_x64.exe`（x86 版もある）を取得する。

### 手元でビルドする

MSVC と Windows SDK が必要。入っていなければ、`install-build-tools.bat` で
Build Tools for Visual Studio（IDE なし）を winget から入れられる。

```
install-build-tools.bat
```

そのあと `build.bat` を実行する。Visual Studio の場所は自動で探す。
Visual Studio 本体（「C++ によるデスクトップ開発」）が入っていれば、上のインストールは不要。

```
build.bat          x64 版を作る（既定）
build.bat x86      x86 版を作る
```

成功すると `opm_hdcp_force_x64.exe`（x86 なら `opm_hdcp_force_x86.exe`）ができる。

## 使い方

通常のコマンドプロンプトから実行する。

```
opm_hdcp_force.exe                  HDCP を ON にし、状態を表示する。Enter キーで OFF にして終了
opm_hdcp_force.exe /off             HDCP の OFF だけを試して終了
opm_hdcp_force.exe /watch           状態を 100 ms 間隔で監視し、HDCP が落ちたら OFF→ON で復帰させる
opm_hdcp_force.exe /watch /interval:50
                                    監視間隔を 50 ms にする
```

- `/watch` は、物理コネクタの実際の保護レベル（actual）と自分の要求値（virtual）を表示する。
  落ちたのを検知すると、OFF を送ってから ON を送り直す。ON の再送だけでは何も起きないため。
- 対象はプライマリモニタ。
