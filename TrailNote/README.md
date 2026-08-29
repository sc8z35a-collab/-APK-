# TrailNote

田舎・自然・森探索や撮影候補地を、通信なしで記録する軽量Androidアプリです。

## v1.3.0 主な機能
- 探索ログの追加・編集・削除・複製
- タイトル / 場所 / タグ / メモ
- お気に入り、撮影済みフラグ
- カード上からお気に入り・撮影状態を即時切替
- 全文検索、お気に入り絞り込み
- 未撮影 / 撮影済み / すべて の状態フィルタ
- 新しい順 / 古い順 の並び替え
- 未撮影ログから「次に撮る候補」をランダム選択
- 記録数 / お気に入り / 撮影済みの簡易統計
- システムのダークモードに追従

## TrailNote Vault セキュリティー
セキュリティー処理は `SecurityVault.java` に分離しています。PIN有効時は単なるUIロックではなく、ログ暗号鍵自体をPINとAndroid Keystoreの二要素で保護します。

- ログ本体はランダム256-bitマスター鍵 + AES-256-GCMで認証付き暗号化
- マスター鍵をAndroid KeystoreのAES鍵でラップ
- さらにKeystoreでラップした鍵を、別salt + PIN由来鍵で二重ラップ
- PIN解除時のみRAMへマスター鍵を展開し、ロック時にbyte配列をゼロ化して破棄
- 6〜12桁PIN。PINそのものは保存しない
- PIN検証: ランダムsalt + PBKDF2WithHmacSHA256 160,000 iterations
- PIN鍵ラップ: 検証用とは別salt + PBKDF2WithHmacSHA256 220,000 iterations
- 連続PIN失敗時の段階的ロックアウト（30秒〜最大480秒）
- バックグラウンド30秒以上で再ロック
- `FLAG_SECURE` で通常のスクリーンショット / 画面録画経路を遮断
- `android:allowBackup=false` / `fullBackupContent=false`
- `usesCleartextTraffic=false`
- v1.xの平文SharedPreferencesデータは暗号化領域へ自動移行し、旧キーを削除
- 復号・整合性エラー発生時はfail-closedし、空データで暗号化領域を上書きしない

## 暗号化バックアップ
- 独自 `.tnvault` 形式
- PINとは別の8文字以上パスフレーズを利用可能
- PBKDF2WithHmacSHA256 220,000 iterations
- AES-256-GCM + 128-bit認証タグ
- 誤パスフレーズ・改ざんはGCM認証で検出
- 10MiBを超える復元入力を拒否

### セキュリティー上の前提
これはアプリ層の強化防御です。root化端末、OS/カーネル自体が侵害された環境、悪意ある改造APK、デバッガを許可した開発用ビルド、物理的な高度解析まで完全に防ぐものではありません。配布用に高い保証が必要な場合は、debug APKではなく専用署名鍵による非debug release APKを使うべきです。

## 権限・通信
- INTERNET権限なし
- 位置情報権限なし
- バックグラウンドサービスなし
- サーバーアカウントなし

## Android
- applicationId: `com.rstlab.trailnote`
- minSdk: 26
- targetSdk: 35
- compileSdk: 35
- Java 17 / Android Gradle Plugin 8.7.3

## APK
GitHub Actionsの `TrailNote Android CI` が `trailnote-v1` ブランチへのpushで lint と debug APK ビルドを実行します。
生成物は `TrailNote-v1-debug-apk` Artifact として保存されます。debug APK はAndroidのdebug keyで署名されるため、そのまま端末へのインストール確認に使えます。
