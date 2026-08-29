# TrailNote

田舎・自然・森探索や撮影候補地を、通信なしで記録する軽量Androidアプリです。

## v1 機能
- 探索ログの追加・編集・削除
- タイトル / 場所 / タグ / メモ
- お気に入り、撮影済みフラグ
- 全文検索、お気に入り絞り込み
- 記録数 / お気に入り / 撮影済みの簡易統計
- JSONバックアップ / 復元（Storage Access Framework）
- システムのダークモードに追従
- INTERNET権限なし
- 位置情報権限なし
- バックグラウンドサービスなし

## Android
- applicationId: `com.rstlab.trailnote`
- minSdk: 26
- targetSdk: 35
- compileSdk: 35
- Java 17 / Android Gradle Plugin 8.7.3

## APK
GitHub Actionsの `TrailNote Android CI` が `trailnote-v1` ブランチへのpushで lint と debug APK ビルドを実行します。
生成物は `TrailNote-v1-debug-apk` Artifact として保存されます。debug APK はAndroidのdebug keyで署名されるため、そのまま端末へのインストール確認に使えます。

## プライバシー方針
v1はネットワーク通信そのものを要求しません。記録データは端末内のSharedPreferencesに保存され、ユーザーが明示的にJSONを書き出した場合のみ指定先へコピーされます。
