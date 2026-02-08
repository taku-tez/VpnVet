# VpnVet 包括チェック・タスクリスト

このタスクリストは、VpnVet を**品質・検知精度・運用性・セキュリティ**の観点で網羅的に点検するための恒久チェックリストです。

> 日時付き実行結果は [`docs/qa-runs/`](docs/qa-runs/) に分離しています。

## 0. 進め方（推奨）

- [ ] まず現行状態のベースライン取得（`npm run build` / `npm test`）
- [ ] 影響範囲が広いもの（型・検知ロジック・脆弱性DB）を優先
- [ ] 最後に CLI UX / ドキュメント / リリース準備をまとめて実施

---

## 1. 品質ゲート（必須）

### 1-1. ビルド・テスト
- [ ] TypeScript ビルドが通る（`npm run build`）
- [ ] 既存テストが全件成功（`npm test`）
- [ ] 失敗時は「再現手順」「原因」「修正方針」を issue 化

### 1-2. 静的品質
- [ ] ESLint 実行環境を整備し `npm run lint` を通す
- [ ] 使われていない export / import を整理
- [ ] 公開 API (`src/index.ts`) の後方互換性を確認

### 1-3. 依存関係
- [ ] `npm audit` で依存の既知脆弱性を確認
- [ ] devDependencies を含む不要依存の削除
- [ ] Node バージョン要件（>=18）で実行確認

---

## 2. 検知ロジック（Fingerprint）

> **コードパス:** `src/fingerprints/` (tier1-enterprise.ts, tier2-enterprise.ts, smb-soho.ts, cloud-ztna.ts, asia.ts)
> **エントリ:** `src/fingerprints/index.ts` → `fingerprints[]`, `getAllVendors()`, `getFingerprintsByVendor()`
> **検知実行:** `src/scanner.ts` → `VpnScanner.detectDeviceForUrl()` → `testPattern()`
> **型定義:** `src/types.ts` → `Fingerprint`, `FingerprintPattern`, `DetectionMethod`

### 2-1. カバレッジ確認
- [ ] 各 vendor の fingerprint が `endpoint/header/body/certificate/favicon` のどれで判定しているか棚卸し
- [ ] 「単一シグネチャ依存」になっている vendor を抽出
- [ ] 低信頼（重みが低い）パターンの誤検知リスクを見直し

### 2-2. 精度改善
- [ ] 強シグネチャ（固有ヘッダ/固有URL）を優先して重み再調整
- [ ] 類似製品間で衝突しやすいパターンを統合・除外
- [ ] 不確実時の `unknown` フォールバック基準を明文化

### 2-3. テスト強化
- [ ] vendor ごとの最小ユニットテストを追加
- [ ] 誤検知（False Positive）ケースを追加
- [ ] 未検知（False Negative）ケースを追加

---

## 3. 脆弱性データ（CVE/KEV）

> **コードパス:** `src/vulnerabilities.ts` → `vulnerabilities[]`
> **判定ロジック:** `src/scanner.ts` → `VpnScanner.checkVulnerabilities()`
> **バージョン比較:** `src/utils.ts` → `compareVersions()`, `isVersionAffected()`, `hasVersionConstraints()`
> **型定義:** `src/types.ts` → `Vulnerability`, `AffectedVersion`, `VulnerabilityMatch`

### 3-1. データ整合性
- [ ] `src/vulnerabilities.ts` の CVE 書式（`CVE-YYYY-NNNN...`）を検証
- [ ] severity / CVSS / references の欠損チェック
- [ ] `affected` の vendor/product 名が fingerprint 側と一致しているか確認

### 3-2. 判定ロジック
- [ ] versionStart/versionEnd の境界条件テスト（含む/含まない）
- [ ] バージョン不明時の判定ポリシーを明確化
- [ ] CISA KEV フラグに基づく優先表示が期待通りか検証

### 3-3. 運用更新フロー
- [ ] CVE 追加時のテンプレート化（入力項目の標準化）
- [ ] 月次更新タスク（KEV 追従）を定例化
- [ ] 変更差分のレビュー観点（誤マッピング防止）を定義

---

## 4. スキャナ実行品質

> **コードパス:** `src/scanner.ts` → `VpnScanner`
> **HTTP:** `httpRequestCore()`, `httpRequestSingle()`, `httpRequestBinarySingle()`
> **SSRF防御:** `resolveSafeAddresses()`, `isUnsafeIP()`, `extractIPv4Mapped()`, `buildPinnedLookup()`
> **並列実行:** `scanMultiple()` (concurrency制御)

### 4-1. ネットワーク挙動
- [ ] タイムアウト時のリトライ方針を確認
- [ ] DNS 失敗/接続拒否/TLS 失敗のエラーメッセージを分類
- [ ] スキャン並列数の既定値と上限値を検討

### 4-2. 実行安定性
- [ ] 大量ターゲット入力時のメモリ使用量を確認
- [ ] 異常レスポンス（巨大HTML/壊れたヘッダ）耐性テスト
- [ ] 途中失敗時でも処理継続できることを確認

### 4-3. パフォーマンス
- [ ] 代表的ターゲット数（1 / 100 / 1000）で所要時間計測
- [ ] ボトルネック（証明書取得・HTTP再試行）を特定
- [ ] キャッシュや短絡判定の導入余地を評価

---

## 5. CLI / 出力フォーマット

> **コードパス:** `src/cli.ts` → `main()`
> **出力フォーマッタ:** `formatSarif()`, `formatJson()`, `formatCsv()`, `formatTable()`
> **SARIF URI正規化:** `normalizeTargetUri()` (SHA-256ハッシュによるinvalid target識別)
> **vendor正規化:** `src/vendor.ts` → `resolveVendor()`, `VENDOR_ALIASES`
> **ログ:** `src/utils.ts` → `logError()`, `logInfo()`, `logProgress()`

### 5-1. CLI UX
- [ ] `scan`, `list vendors`, `list vulns`, `version` の主要動線を手動検証
- [ ] 引数の不正値（未知フォーマット、空ターゲット）時のヘルプ表示改善
- [ ] `--quiet` 時に必要最小限のログのみ出ることを確認

### 5-2. 出力整合
- [ ] JSON 出力のスキーマ安定性確認
- [ ] SARIF の主要フィールド（ruleId, level, location）妥当性確認
- [ ] CSV の列順・エスケープ・改行耐性確認
- [ ] table 表示の可読性（長い説明文）確認

### 5-3. 終了コード
- [ ] 0/1/2 の条件が README 記載と一致するか検証
- [ ] クリティカル混在時の優先終了コードをテスト

---

## 6. ドキュメント整備

### 6-1. README
- [ ] サポート vendor 数と実装実態を突合（`node scripts/count-stats.mjs`）
- [ ] 使用例が現行 CLI 仕様と一致するか確認
- [ ] API サンプルの型定義と実装差異を確認

### 6-2. CONTRIBUTING
- [ ] 「新規 vendor 追加手順」と実コード構成の整合性確認
- [ ] テスト追加箇所・命名規則を補足
- [ ] コミット規約例を現状運用に合わせて更新

### 6-3. CHANGELOG
- [ ] 直近バージョンの更新内容が反映されているか確認
- [ ] 破壊的変更の有無を明記

---

## 7. セキュリティ・コンプライアンス

- [ ] 外部入力（ターゲットファイル、CLI引数）のバリデーション確認
- [ ] SSRF 的な意図しない接続先拡張が起きない設計か確認
- [ ] ログに機微情報（内部IP/トークン）が残らないことを確認
- [ ] ライセンス表記（MIT）と配布物整合性を確認

---

## 8. CI/CD・リリース運用

- [ ] CI で build/test/lint を必須化
- [ ] Node LTS 複数バージョンでマトリクステスト
- [ ] リリース前チェック（バージョン、changelog、タグ）をテンプレート化
- [ ] npm publish 前に dry-run を実施

---

## 9. 優先度付き実行順（初回推奨）

### P0（今すぐ）
- [ ] build/test の常時グリーン化
- [ ] fingerprint と vulnerability の対応関係監査
- [ ] 終了コードと README の整合性検証

### P1（短期）
- [ ] 誤検知/未検知テスト拡充
- [ ] SARIF/JSON/CSV 出力のスキーマ固定化
- [ ] エラー分類とメッセージ改善

### P2（中期）
- [ ] パフォーマンス計測と最適化
- [ ] CVE 更新の半自動化
- [ ] CI/CD リリースチェックリスト整備

### CVE未対応ベンダー整備バックログ (#5)

以下21ベンダーは検出可能だがCVEマッピングが未整備。`scripts/audit-coverage.mjs --kev` で KEV該当を確認可能。

**優先度高（KEV該当の可能性あり）:**
- [ ] h3c - SecPath
- [ ] hillstone - NGFW
- [ ] ruijie - RG
- [ ] stormshield - SNS
- [ ] ubiquiti - UniFi

**優先度中:**
- [ ] ahnlab - TrusGuard
- [ ] dptech - UTM
- [ ] endian - UTM
- [ ] kerio - Control
- [ ] lancom - VPN
- [ ] meraki - MX (Cisco子会社、Cisco CVEと重複可能性)
- [ ] nsfocus - WAF/UTM
- [ ] openvpn - Access Server
- [ ] secui - MF2
- [ ] topsec - NGFW
- [ ] venustech - UTM

**優先度低（ZTNA/クラウド、CVE形態が異なる）:**
- [ ] cloudflare - Access
- [ ] netmotion - Mobility
- [ ] opnsense - Firewall
- [ ] untangle - NG Firewall
- [ ] zscaler - ZPA

---

## 10. 完了定義（Definition of Done）

- [ ] 必須チェック（P0）がすべて完了
- [ ] 追加/変更したロジックに対してテストが存在
- [ ] README/CHANGELOG が実装と一致
- [ ] 再現可能な手順で第三者が同じ結果を得られる

---

## 実行ログ

| 日付 | ログ |
|------|------|
| 2026-02-08 | [docs/qa-runs/2026-02-08.md](docs/qa-runs/2026-02-08.md) |
