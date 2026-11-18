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

`opm_hdcp_force_x64.exe` をダブルクリックすると、ターミナルではなく小さなウィンドウが開く。

- 起動すると、プライマリモニタの出力に対して OPM セッションを確立する
- **HDCP ON** / **HDCP OFF** ボタンで HDCP を切り替える
- 上部のカードに現在の状態を表示する（緑: ON / 灰: OFF / 黄: 認証待ち・復帰待ち / 赤: エラー）
  - `actual` は物理コネクタの実際の保護レベル、`virtual` はこのアプリが要求している値
  - ドロップ回数と、落ちていた時間の合計も表示する
- **自動復帰** にチェックを入れると、指定した間隔で状態を監視し、HDCP が落ちたら OFF→ON を送り直す
  （ON の再送だけでは何も起きないため）。落ちたままのときは 1 秒おきに再試行する
- **再接続** で OPM セッションを張り直す（ディスプレイ構成を変えたときやエラー時に）
- ウィンドウを閉じると HDCP を OFF にしてから終了する
- 下のログ欄はテキストを選択してコピーできる

起動オプション（ショートカットのリンク先に付けても使える）:

```
opm_hdcp_force.exe /on              起動と同時に HDCP を ON にする
opm_hdcp_force.exe /watch           自動復帰を有効にした状態で起動する
opm_hdcp_force.exe /interval:50     自動復帰の監視間隔を 50 ms にする（既定 100 ms）
opm_hdcp_force.exe /cert:N          OPM 証明書チェーンの N 番目を使う（デバッグ用）
```

## 仮想マシンでの動作について

OPM / HDCP は実 GPU のドライバと物理的な映像出力が必要なため、Hyper-V・VirtualBox・VMware などの
仮想 GPU、リモートデスクトップ接続、Microsoft Basic Display Adapter では動かない
（起動はするが「エラー」表示になる）。HDCP の実際の動作確認は実機で行うこと。
