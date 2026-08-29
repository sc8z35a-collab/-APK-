# TrailNote

田舎・自然・森探索や撮影候補地を、通信なしで記録する軽量Androidアプリです。

## v1.2.0 主な機能
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
TrailNote v1.2.0では、セキュリティー処理を `SecurityVault.java` に分離しています。

- ログデータをAES-256-GCMで暗号化して端末内へ保存
- AES鍵はAndroid Keystore内で生成・保持
- v1.xの平文SharedPreferencesデータは初回アクセス時に暗号化領域へ移行し、旧キーを削除
- 6〜12桁PINロック
- PINは平文保存せず、ランダムsalt + PBKDF2WithHmacSHA256（140,000 iterations）の検証値のみ保存
- 連続PIN失敗時の段階的ロックアウト
- バックグラウンド30秒以上で再ロック
- `FLAG_SECURE` により通常のスクリーンショット / 画面録画経路から内容を保護
- バックアップは独自 `.tnvault` 形式
- バックアップは別パスフレーズ + PBKDF2WithHmacSHA256（180,000 iterations）+ AES-256-GCMで暗号化
- バックアップ復元時はGCM認証タグで改ざん / 誤パスフレーズを検出
- 10MiBを超える復元入力を拒否

### セキュリティー上の前提
この機構は端末内データを保護するアプリ層の防御です。root化端末、OS自体が侵害された環境、デバッガ/改造APK、物理的な高度解析まで完全に防ぐものではありません。

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
