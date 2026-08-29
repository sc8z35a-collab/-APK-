package com.rstlab.trailnote;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;
import java.util.Random;
import java.util.UUID;

public class MainActivity extends Activity {
    private static final String PREFS = "trailnote_prefs";
    private static final String KEY_ENTRIES = "entries";
    private static final int REQ_EXPORT_VAULT = 301;
    private static final int REQ_IMPORT_VAULT = 302;
    private static final long AUTO_LOCK_MS = 30_000L;

    private SharedPreferences prefs;
    private SecurityVault vault;
    private EditText titleInput, placeInput, tagsInput, memoInput, searchInput;
    private CheckBox favoriteInput, filmedInput, favoriteOnly;
    private TextView totalValue, favoriteValue, filmedValue, resultsLabel, formModeLabel;
    private TextView securityStatus, filterStatus;
    private LinearLayout listContainer;
    private String selectedId;
    private boolean dark;
    private boolean unlocked;
    private boolean vaultReadError;
    private long backgroundAt;
    private int filterMode;
    private boolean sortNewest = true;
    private String pendingBackupPassphrase;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        vault = new SecurityVault(this);
        dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        styleSystemBars();
        if (vault.hasPin()) {
            unlocked = false;
            showLockScreen();
        } else {
            unlocked = true;
            buildUi();
            render();
            showFirstRunSecuritySetup();
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
        if (backgroundAt > 0L && unlocked && vault.hasPin()
                && System.currentTimeMillis() - backgroundAt >= AUTO_LOCK_MS) {
            unlocked = false;
            showLockScreen();
        }
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (vault != null && vault.hasPin()) backgroundAt = System.currentTimeMillis();
    }

    private void styleSystemBars() {
        Window w = getWindow();
        w.setStatusBarColor(bg());
        w.setNavigationBarColor(bg());
        int flags = 0;
        if (!dark) flags |= View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
        if (!dark) flags |= View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        w.getDecorView().setSystemUiVisibility(flags);
    }

    private void showLockScreen() {
        vault.lockSession();
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(dp(28), dp(70), dp(28), dp(28));
        root.setBackgroundColor(bg());

        TextView shield = text("TN", 24, true);
        shield.setTextColor(Color.WHITE);
        shield.setGravity(Gravity.CENTER);
        shield.setBackground(round(accent(), dp(22), 0, Color.TRANSPARENT));
        root.addView(shield, new LinearLayout.LayoutParams(dp(72), dp(72)));

        TextView title = text("TrailNote Vault", 28, true);
        title.setGravity(Gravity.CENTER);
        root.addView(title, topMargin(20));

        TextView desc = text("暗号化された探索ログを開くにはPINを入力してください。", 14, false);
        desc.setTextColor(muted());
        desc.setGravity(Gravity.CENTER);
        root.addView(desc, topMargin(7));

        EditText pin = pinEdit("6〜12桁のPIN");
        root.addView(pin, topMargin(24));

        TextView lockInfo = text("", 12, true);
        lockInfo.setTextColor(danger());
        lockInfo.setGravity(Gravity.CENTER);
        root.addView(lockInfo, topMargin(8));

        Button unlockBtn = actionButton("ロック解除", ButtonStyle.PRIMARY);
        root.addView(unlockBtn, topMargin(14));

        TextView security = text("AES-256-GCM • Android Keystore • Screenshot Shield", 11, true);
        security.setTextColor(muted());
        security.setGravity(Gravity.CENTER);
        root.addView(security, topMargin(24));

        Runnable updateLockInfo = () -> {
            if (vault.isLockedOut()) {
                long sec = Math.max(1L, (vault.lockoutUntil() - System.currentTimeMillis() + 999L) / 1000L);
                lockInfo.setText("連続失敗のため約 " + sec + " 秒ロック中");
            } else if (vault.failedAttempts() > 0) {
                lockInfo.setText("PIN失敗 " + vault.failedAttempts() + " 回");
            } else {
                lockInfo.setText("");
            }
        };
        updateLockInfo.run();

        unlockBtn.setOnClickListener(v -> {
            try {
                if (vault.isLockedOut()) {
                    updateLockInfo.run();
                    toast("一時ロック中です");
                    return;
                }
                if (vault.verifyPin(pin.getText().toString())) {
                    unlocked = true;
                    backgroundAt = 0L;
                    buildUi();
                    render();
                    toast("TrailNote Vaultを解除しました");
                } else {
                    pin.setText("");
                    updateLockInfo.run();
                    toast("PINが違います");
                }
            } catch (Exception e) {
                toast("ロック解除に失敗しました");
            }
        });

        setContentView(root);
    }

    private void showFirstRunSecuritySetup() {
        new AlertDialog.Builder(this)
                .setTitle("TrailNote Vaultを有効化")
                .setMessage("ログ本体はすでにAndroid Keystoreで暗号化保存されます。さらにPINロックと30秒自動ロックを有効にできます。")
                .setNegativeButton("あとで", null)
                .setPositiveButton("PINを設定", (d, w) -> showSetPinDialog())
                .show();
    }

    private void showSetPinDialog() {
        boolean changing = vault.hasPin();
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(20), dp(8), dp(20), 0);

        EditText current = null;
        if (changing) {
            current = pinEdit("現在のPIN");
            box.addView(current, topMargin(6));
        }
        EditText next = pinEdit("新しいPIN（6〜12桁）");
        EditText confirm = pinEdit("新しいPINを再入力");
        box.addView(next, topMargin(10));
        box.addView(confirm, topMargin(10));

        final EditText currentFinal = current;
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(changing ? "PINを変更" : "PINを設定")
                .setMessage("PINそのものは保存せず、PBKDF2-SHA256で検証値のみを保存します。")
                .setView(box)
                .setNegativeButton("キャンセル", null)
                .setPositiveButton("保存", null)
                .create();
        dialog.setOnShowListener(x -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            try {
                if (changing && !vault.verifyPin(currentFinal.getText().toString())) {
                    toast("現在のPINが違います");
                    return;
                }
                String a = next.getText().toString();
                String b = confirm.getText().toString();
                if (!a.equals(b)) {
                    toast("新しいPINが一致しません");
                    return;
                }
                vault.setPin(a);
                refreshSecurityStatus();
                dialog.dismiss();
                toast(changing ? "PINを変更しました" : "PINロックを有効にしました");
            } catch (Exception e) {
                toast(e.getMessage() == null ? "PIN設定に失敗しました" : e.getMessage());
            }
        }));
        dialog.show();
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        scroll.setBackgroundColor(bg());

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(14), dp(16), dp(42));
        scroll.addView(root, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        root.addView(buildHero());
        root.addView(buildStats(), topMargin(12));

        root.addView(sectionHeader("SECURITY", "TrailNote Vault"), topMargin(28));
        root.addView(buildSecurityCard(), topMargin(10));

        root.addView(sectionHeader("LOG EDITOR", "探索ログを追加・編集"), topMargin(28));
        root.addView(buildEditorCard(), topMargin(10));

        root.addView(sectionHeader("LIBRARY", "記録を探す・絞り込む"), topMargin(28));
        root.addView(buildSearchCard(), topMargin(10));

        LinearLayout listHeader = new LinearLayout(this);
        listHeader.setOrientation(LinearLayout.HORIZONTAL);
        listHeader.setGravity(Gravity.CENTER_VERTICAL);
        TextView listTitle = text("探索ログ", 20, true);
        listHeader.addView(listTitle, weight());
        resultsLabel = text("0件", 13, true);
        resultsLabel.setTextColor(accent());
        resultsLabel.setGravity(Gravity.END | Gravity.CENTER_VERTICAL);
        listHeader.addView(resultsLabel, wrap());
        root.addView(listHeader, topMargin(24));

        listContainer = new LinearLayout(this);
        listContainer.setOrientation(LinearLayout.VERTICAL);
        root.addView(listContainer, topMargin(4));

        LinearLayout privacyCard = panel(dp(14), surface2(), false);
        privacyCard.setGravity(Gravity.CENTER_HORIZONTAL);
        TextView privacyTitle = text("LOCAL ENCRYPTED VAULT", 11, true);
        privacyTitle.setTextColor(accent());
        privacyTitle.setLetterSpacing(0.11f);
        privacyTitle.setGravity(Gravity.CENTER);
        privacyCard.addView(privacyTitle);
        TextView privacy = text("通信権限なし・位置情報権限なし・画面キャプチャ防止", 12, false);
        privacy.setTextColor(muted());
        privacy.setGravity(Gravity.CENTER);
        privacyCard.addView(privacy, topMargin(5));
        root.addView(privacyCard, topMargin(26));

        setContentView(scroll);
    }

    private View buildHero() {
        LinearLayout hero = panel(dp(20), heroBg(), true);
        hero.setPadding(dp(20), dp(20), dp(20), dp(20));

        LinearLayout top = new LinearLayout(this);
        top.setOrientation(LinearLayout.HORIZONTAL);
        top.setGravity(Gravity.CENTER_VERTICAL);

        TextView mark = text("TN", 16, true);
        mark.setGravity(Gravity.CENTER);
        mark.setTextColor(Color.WHITE);
        mark.setBackground(round(accent(), dp(14), 0, Color.TRANSPARENT));
        top.addView(mark, new LinearLayout.LayoutParams(dp(48), dp(48)));

        LinearLayout titles = new LinearLayout(this);
        titles.setOrientation(LinearLayout.VERTICAL);
        TextView brand = text("TrailNote", 29, true);
        brand.setLetterSpacing(-0.02f);
        titles.addView(brand);
        TextView tagline = text("Explore. Capture. Protect.", 13, false);
        tagline.setTextColor(muted());
        titles.addView(tagline, topMargin(1));
        LinearLayout.LayoutParams tp = weight();
        tp.leftMargin = dp(14);
        top.addView(titles, tp);
        hero.addView(top);

        TextView lead = text("森・田舎・撮影スポットを、暗号化された自分だけの探索ライブラリに。", 15, false);
        lead.setTextColor(fg());
        lead.setLineSpacing(0, 1.2f);
        hero.addView(lead, topMargin(18));

        TextView badge = text("●  KEYSTORE ENCRYPTED", 11, true);
        badge.setTextColor(accent());
        badge.setPadding(dp(10), dp(6), dp(10), dp(6));
        badge.setBackground(round(accentSoft(), dp(20), 0, Color.TRANSPARENT));
        LinearLayout.LayoutParams bp = wrap();
        bp.topMargin = dp(14);
        hero.addView(badge, bp);
        return hero;
    }

    private View buildStats() {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);

        StatBlock total = statBlock("TOTAL", "0", "記録");
        totalValue = total.value;
        row.addView(total.root, weightWithRight(8));

        StatBlock fav = statBlock("FAVORITE", "0", "お気に入り");
        favoriteValue = fav.value;
        row.addView(fav.root, weightWithRight(8));

        StatBlock filmed = statBlock("FILMED", "0", "撮影済み");
        filmedValue = filmed.value;
        row.addView(filmed.root, weight());
        return row;
    }

    private View buildSecurityCard() {
        LinearLayout card = panel(dp(18), cardBg(), true);
        card.setPadding(dp(16), dp(16), dp(16), dp(16));

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        TextView title = text("独立ローカルセキュリティー", 16, true);
        header.addView(title, weight());
        securityStatus = text("", 11, true);
        securityStatus.setPadding(dp(9), dp(5), dp(9), dp(5));
        header.addView(securityStatus, wrap());
        card.addView(header);

        TextView crypto = text(vault.securitySummary(), 12, false);
        crypto.setTextColor(muted());
        card.addView(crypto, topMargin(7));

        TextView protection = text("ログ本体を暗号化保存 / 画面キャプチャ防止 / PIN失敗ロックアウト / 30秒自動再ロック", 13, false);
        protection.setTextColor(secondaryText());
        protection.setLineSpacing(0, 1.15f);
        card.addView(protection, topMargin(8));

        LinearLayout buttons = new LinearLayout(this);
        buttons.setOrientation(LinearLayout.HORIZONTAL);
        Button pinBtn = actionButton(vault.hasPin() ? "PIN変更" : "PIN設定", ButtonStyle.SECONDARY);
        Button lockBtn = actionButton("今すぐロック", ButtonStyle.SECONDARY);
        buttons.addView(pinBtn, weightWithRight(8));
        buttons.addView(lockBtn, weight());
        card.addView(buttons, topMargin(12));
        pinBtn.setOnClickListener(v -> showSetPinDialog());
        lockBtn.setOnClickListener(v -> {
            if (!vault.hasPin()) {
                showSetPinDialog();
                return;
            }
            unlocked = false;
            showLockScreen();
        });

        TextView backupLabel = text("ENCRYPTED BACKUP", 10, true);
        backupLabel.setTextColor(muted());
        backupLabel.setLetterSpacing(0.10f);
        card.addView(backupLabel, topMargin(14));

        LinearLayout backup = new LinearLayout(this);
        backup.setOrientation(LinearLayout.HORIZONTAL);
        Button exportBtn = actionButton("暗号化書き出し", ButtonStyle.SECONDARY);
        Button importBtn = actionButton("暗号化復元", ButtonStyle.SECONDARY);
        backup.addView(exportBtn, weightWithRight(8));
        backup.addView(importBtn, weight());
        card.addView(backup, topMargin(6));
        exportBtn.setOnClickListener(v -> requestEncryptedExport());
        importBtn.setOnClickListener(v -> requestEncryptedImport());

        refreshSecurityStatus();
        return card;
    }

    private void refreshSecurityStatus() {
        if (securityStatus == null) return;
        boolean pin = vault.hasPin();
        securityStatus.setText(pin ? "LOCK ON" : "ENCRYPTED");
        securityStatus.setTextColor(pin ? success() : accent());
        securityStatus.setBackground(round(pin ? successSoft() : accentSoft(), dp(15), 0, Color.TRANSPARENT));
    }

    private View buildEditorCard() {
        LinearLayout card = panel(dp(18), cardBg(), true);
        card.setPadding(dp(16), dp(16), dp(16), dp(16));

        LinearLayout mode = new LinearLayout(this);
        mode.setOrientation(LinearLayout.HORIZONTAL);
        mode.setGravity(Gravity.CENTER_VERTICAL);
        TextView modeTitle = text("記録内容", 17, true);
        mode.addView(modeTitle, weight());
        formModeLabel = text("新規作成", 12, true);
        formModeLabel.setTextColor(accent());
        formModeLabel.setPadding(dp(9), dp(5), dp(9), dp(5));
        formModeLabel.setBackground(round(accentSoft(), dp(16), 0, Color.TRANSPARENT));
        mode.addView(formModeLabel, wrap());
        card.addView(mode);

        card.addView(fieldLabel("タイトル", true), topMargin(16));
        titleInput = edit("例：旧林道の夕景スポット", false);
        card.addView(titleInput, topMargin(6));

        card.addView(fieldLabel("場所・エリア", false), topMargin(13));
        placeInput = edit("例：○○市 北部林道", false);
        card.addView(placeInput, topMargin(6));

        card.addView(fieldLabel("タグ", false), topMargin(13));
        tagsInput = edit("森, 廃道, 夕景", false);
        card.addView(tagsInput, topMargin(6));

        card.addView(fieldLabel("撮影メモ", false), topMargin(13));
        memoInput = edit("ルート、光の向き、危険箇所、次回撮りたいカットなど", true);
        card.addView(memoInput, topMargin(6));

        LinearLayout checks = new LinearLayout(this);
        checks.setOrientation(LinearLayout.HORIZONTAL);
        favoriteInput = check("★ お気に入り");
        filmedInput = check("✓ 撮影済み");
        checks.addView(favoriteInput, weightWithRight(4));
        checks.addView(filmedInput, weight());
        card.addView(checks, topMargin(10));

        Button saveBtn = actionButton("暗号化して保存", ButtonStyle.PRIMARY);
        card.addView(saveBtn, topMargin(12));
        saveBtn.setOnClickListener(v -> saveEntry());

        LinearLayout secondaryActions = new LinearLayout(this);
        secondaryActions.setOrientation(LinearLayout.HORIZONTAL);
        Button newBtn = actionButton("新規に戻す", ButtonStyle.SECONDARY);
        Button deleteBtn = actionButton("削除", ButtonStyle.DANGER_GHOST);
        secondaryActions.addView(newBtn, weightWithRight(8));
        secondaryActions.addView(deleteBtn, weight());
        card.addView(secondaryActions, topMargin(8));
        newBtn.setOnClickListener(v -> clearForm());
        deleteBtn.setOnClickListener(v -> confirmDelete());
        return card;
    }

    private View buildSearchCard() {
        LinearLayout card = panel(dp(18), cardBg(), true);
        card.setPadding(dp(16), dp(16), dp(16), dp(16));

        searchInput = edit("検索：タイトル / 場所 / タグ / メモ", false);
        card.addView(searchInput);
        favoriteOnly = check("★ お気に入りだけ表示");
        card.addView(favoriteOnly, topMargin(6));

        filterStatus = text("表示: すべて • 新しい順", 12, true);
        filterStatus.setTextColor(accent());
        card.addView(filterStatus, topMargin(6));

        LinearLayout filters = new LinearLayout(this);
        filters.setOrientation(LinearLayout.HORIZONTAL);
        Button stateBtn = actionButton("状態フィルタ", ButtonStyle.SECONDARY);
        Button sortBtn = actionButton("並び替え", ButtonStyle.SECONDARY);
        filters.addView(stateBtn, weightWithRight(8));
        filters.addView(sortBtn, weight());
        card.addView(filters, topMargin(8));

        Button nextBtn = actionButton("🎯 次に撮る候補をランダム選択", ButtonStyle.PRIMARY);
        card.addView(nextBtn, topMargin(8));

        searchInput.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) { render(); }
            @Override public void afterTextChanged(Editable s) {}
        });
        favoriteOnly.setOnCheckedChangeListener((buttonView, isChecked) -> render());
        stateBtn.setOnClickListener(v -> {
            filterMode = (filterMode + 1) % 3;
            updateFilterStatus();
            render();
        });
        sortBtn.setOnClickListener(v -> {
            sortNewest = !sortNewest;
            updateFilterStatus();
            render();
        });
        nextBtn.setOnClickListener(v -> pickNextToShoot());

        return card;
    }

    private void updateFilterStatus() {
        if (filterStatus == null) return;
        String state = filterMode == 1 ? "未撮影" : filterMode == 2 ? "撮影済み" : "すべて";
        filterStatus.setText("表示: " + state + " • " + (sortNewest ? "新しい順" : "古い順"));
    }

    private void pickNextToShoot() {
        try {
            JSONArray all = load();
            ArrayList<JSONObject> candidates = new ArrayList<>();
            for (int i = 0; i < all.length(); i++) {
                JSONObject o = all.optJSONObject(i);
                if (o != null && !o.optBoolean("filmed")) candidates.add(o);
            }
            if (candidates.isEmpty()) {
                toast("未撮影の候補がありません");
                return;
            }
            JSONObject pick = candidates.get(new Random().nextInt(candidates.size()));
            selectEntry(pick);
            toast("次の候補: " + pick.optString("title", "無題"));
        } catch (Exception e) {
            toast("候補選択に失敗しました");
        }
    }

    private void saveEntry() {
        String title = titleInput.getText().toString().trim();
        if (title.isEmpty()) {
            toast("タイトルを入力してください");
            return;
        }
        try {
            JSONArray all = load();
            JSONObject target = null;
            boolean isNew = selectedId == null;
            if (!isNew) target = findById(all, selectedId);
            if (target == null) {
                target = new JSONObject();
                selectedId = UUID.randomUUID().toString();
                target.put("id", selectedId);
                target.put("createdAt", System.currentTimeMillis());
                all.put(target);
                isNew = true;
            }
            target.put("title", title);
            target.put("place", placeInput.getText().toString().trim());
            target.put("tags", tagsInput.getText().toString().trim());
            target.put("memo", memoInput.getText().toString().trim());
            target.put("favorite", favoriteInput.isChecked());
            target.put("filmed", filmedInput.isChecked());
            target.put("updatedAt", System.currentTimeMillis());
            persist(all);
            updateFormMode();
            render();
            toast(isNew ? "暗号化して保存しました" : "暗号化データを更新しました");
        } catch (Exception e) {
            toast("保存に失敗しました: " + e.getMessage());
        }
    }

    private void confirmDelete() {
        if (selectedId == null) {
            toast("削除する記録を一覧から選択してください");
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("この探索ログを削除しますか？")
                .setMessage("この操作は元に戻せません。")
                .setNegativeButton("キャンセル", null)
                .setPositiveButton("削除", (d, which) -> deleteSelected())
                .show();
    }

    private void deleteSelected() {
        try {
            JSONArray all = load();
            for (int i = 0; i < all.length(); i++) {
                JSONObject o = all.optJSONObject(i);
                if (o != null && selectedId.equals(o.optString("id"))) {
                    all.remove(i);
                    break;
                }
            }
            persist(all);
            clearForm();
            render();
            toast("削除しました");
        } catch (Exception e) {
            toast("削除に失敗しました");
        }
    }

    private void toggleFavorite(String id) {
        try {
            JSONArray all = load();
            JSONObject o = findById(all, id);
            if (o == null) return;
            o.put("favorite", !o.optBoolean("favorite"));
            o.put("updatedAt", System.currentTimeMillis());
            persist(all);
            render();
        } catch (Exception e) {
            toast("更新に失敗しました");
        }
    }

    private void toggleFilmed(String id) {
        try {
            JSONArray all = load();
            JSONObject o = findById(all, id);
            if (o == null) return;
            o.put("filmed", !o.optBoolean("filmed"));
            o.put("updatedAt", System.currentTimeMillis());
            persist(all);
            if (id.equals(selectedId)) filmedInput.setChecked(o.optBoolean("filmed"));
            render();
        } catch (Exception e) {
            toast("更新に失敗しました");
        }
    }

    private void duplicateEntry(String id) {
        try {
            JSONArray all = load();
            JSONObject src = findById(all, id);
            if (src == null) return;
            JSONObject copy = new JSONObject();
            copy.put("id", UUID.randomUUID().toString());
            copy.put("title", src.optString("title") + "（コピー）");
            copy.put("place", src.optString("place"));
            copy.put("tags", src.optString("tags"));
            copy.put("memo", src.optString("memo"));
            copy.put("favorite", src.optBoolean("favorite"));
            copy.put("filmed", false);
            copy.put("createdAt", System.currentTimeMillis());
            copy.put("updatedAt", System.currentTimeMillis());
            all.put(copy);
            persist(all);
            render();
            toast("複製しました");
        } catch (Exception e) {
            toast("複製に失敗しました");
        }
    }

    private void clearForm() {
        selectedId = null;
        titleInput.setText("");
        placeInput.setText("");
        tagsInput.setText("");
        memoInput.setText("");
        favoriteInput.setChecked(false);
        filmedInput.setChecked(false);
        updateFormMode();
        render();
    }

    private void selectEntry(JSONObject o) {
        selectedId = o.optString("id", null);
        titleInput.setText(o.optString("title"));
        placeInput.setText(o.optString("place"));
        tagsInput.setText(o.optString("tags"));
        memoInput.setText(o.optString("memo"));
        favoriteInput.setChecked(o.optBoolean("favorite"));
        filmedInput.setChecked(o.optBoolean("filmed"));
        updateFormMode();
        render();
    }

    private void updateFormMode() {
        if (formModeLabel == null) return;
        formModeLabel.setText(selectedId == null ? "新規作成" : "編集中");
        formModeLabel.setTextColor(selectedId == null ? accent() : selectedAccent());
        formModeLabel.setBackground(round(selectedId == null ? accentSoft() : selectedSoft(), dp(16), 0, Color.TRANSPARENT));
    }

    private void render() {
        if (listContainer == null) return;
        try {
            JSONArray all = load();
            int fav = 0, filmed = 0;
            for (int i = 0; i < all.length(); i++) {
                JSONObject o = all.optJSONObject(i);
                if (o == null) continue;
                if (o.optBoolean("favorite")) fav++;
                if (o.optBoolean("filmed")) filmed++;
            }
            totalValue.setText(String.valueOf(all.length()));
            favoriteValue.setText(String.valueOf(fav));
            filmedValue.setText(String.valueOf(filmed));

            listContainer.removeAllViews();
            String q = searchInput == null ? "" : searchInput.getText().toString().trim().toLowerCase(Locale.ROOT);
            boolean favOnly = favoriteOnly != null && favoriteOnly.isChecked();
            int shown = 0;

            int start = sortNewest ? all.length() - 1 : 0;
            int end = sortNewest ? -1 : all.length();
            int step = sortNewest ? -1 : 1;
            for (int i = start; i != end; i += step) {
                JSONObject o = all.optJSONObject(i);
                if (o == null) continue;
                if (favOnly && !o.optBoolean("favorite")) continue;
                if (filterMode == 1 && o.optBoolean("filmed")) continue;
                if (filterMode == 2 && !o.optBoolean("filmed")) continue;
                String hay = (o.optString("title") + " " + o.optString("place") + " "
                        + o.optString("tags") + " " + o.optString("memo")).toLowerCase(Locale.ROOT);
                if (!q.isEmpty() && !hay.contains(q)) continue;
                listContainer.addView(entryCard(o), topMargin(10));
                shown++;
            }
            resultsLabel.setText(shown + "件");
            updateFilterStatus();
            if (shown == 0) listContainer.addView(emptyState(all.length() == 0), topMargin(10));
        } catch (Exception e) {
            resultsLabel.setText("エラー");
        }
    }

    private View entryCard(JSONObject o) {
        boolean selected = selectedId != null && selectedId.equals(o.optString("id"));
        boolean filmed = o.optBoolean("filmed");
        boolean favorite = o.optBoolean("favorite");
        String id = o.optString("id");

        LinearLayout outer = new LinearLayout(this);
        outer.setOrientation(LinearLayout.HORIZONTAL);
        outer.setBackground(round(selected ? selectedCardBg() : cardBg(), dp(18), dp(1), selected ? selectedAccent() : border()));
        outer.setElevation(dp(selected ? 4 : 2));

        View accentBar = new View(this);
        accentBar.setBackground(round(favorite ? accent() : (filmed ? success() : border()), dp(12), 0, Color.TRANSPARENT));
        LinearLayout.LayoutParams barParams = new LinearLayout.LayoutParams(dp(5), ViewGroup.LayoutParams.MATCH_PARENT);
        barParams.leftMargin = dp(8);
        barParams.topMargin = dp(10);
        barParams.bottomMargin = dp(10);
        outer.addView(accentBar, barParams);

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(13), dp(14), dp(14), dp(14));
        outer.addView(content, weight());

        LinearLayout titleRow = new LinearLayout(this);
        titleRow.setOrientation(LinearLayout.HORIZONTAL);
        titleRow.setGravity(Gravity.CENTER_VERTICAL);
        TextView title = text((favorite ? "★ " : "") + o.optString("title", "無題"), 18, true);
        title.setMaxLines(2);
        titleRow.addView(title, weight());

        TextView state = text(filmed ? "撮影済み" : "未撮影", 11, true);
        state.setTextColor(filmed ? success() : muted());
        state.setPadding(dp(9), dp(5), dp(9), dp(5));
        state.setBackground(round(filmed ? successSoft() : surface2(), dp(14), 0, Color.TRANSPARENT));
        LinearLayout.LayoutParams stateParams = wrap();
        stateParams.leftMargin = dp(8);
        titleRow.addView(state, stateParams);
        content.addView(titleRow);

        String place = o.optString("place");
        long created = o.optLong("createdAt", 0L);
        String meta = format(created);
        if (!place.isEmpty()) meta += "  ·  " + place;
        TextView metaView = text(meta, 12, false);
        metaView.setTextColor(muted());
        content.addView(metaView, topMargin(6));

        String tags = o.optString("tags");
        if (!tags.trim().isEmpty()) content.addView(tagRow(tags), topMargin(9));

        String memo = o.optString("memo");
        if (!memo.isEmpty()) {
            TextView memoView = text(memo.length() > 180 ? memo.substring(0, 180) + "…" : memo, 14, false);
            memoView.setTextColor(secondaryText());
            memoView.setLineSpacing(0, 1.15f);
            content.addView(memoView, topMargin(10));
        }

        LinearLayout quick = new LinearLayout(this);
        quick.setOrientation(LinearLayout.HORIZONTAL);
        Button favBtn = miniButton(favorite ? "★解除" : "★追加");
        Button filmBtn = miniButton(filmed ? "未撮影へ" : "撮影済み");
        Button copyBtn = miniButton("複製");
        quick.addView(favBtn, weightWithRight(6));
        quick.addView(filmBtn, weightWithRight(6));
        quick.addView(copyBtn, weight());
        content.addView(quick, topMargin(11));
        favBtn.setOnClickListener(v -> toggleFavorite(id));
        filmBtn.setOnClickListener(v -> toggleFilmed(id));
        copyBtn.setOnClickListener(v -> duplicateEntry(id));

        TextView hint = text(selected ? "● 編集中" : "カード本体をタップして編集", 11, true);
        hint.setTextColor(selected ? selectedAccent() : muted());
        content.addView(hint, topMargin(9));

        outer.setOnClickListener(v -> selectEntry(o));
        return outer;
    }

    private View tagRow(String raw) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        String[] parts = raw.split(",");
        int added = 0;
        for (String p : parts) {
            String t = p.trim();
            if (t.isEmpty()) continue;
            if (added >= 4) break;
            TextView chip = text("#" + t, 11, true);
            chip.setTextColor(accent());
            chip.setPadding(dp(8), dp(4), dp(8), dp(4));
            chip.setBackground(round(accentSoft(), dp(13), 0, Color.TRANSPARENT));
            LinearLayout.LayoutParams cp = wrap();
            if (added > 0) cp.leftMargin = dp(6);
            row.addView(chip, cp);
            added++;
        }
        if (parts.length > 4) {
            TextView more = text("+" + (parts.length - 4), 11, true);
            more.setTextColor(muted());
            LinearLayout.LayoutParams mp = wrap();
            mp.leftMargin = dp(6);
            row.addView(more, mp);
        }
        return row;
    }

    private View emptyState(boolean trulyEmpty) {
        LinearLayout empty = panel(dp(18), cardBg(), false);
        empty.setGravity(Gravity.CENTER_HORIZONTAL);
        empty.setPadding(dp(20), dp(28), dp(20), dp(28));
        TextView icon = text(trulyEmpty ? "＋" : "⌕", 26, true);
        icon.setGravity(Gravity.CENTER);
        icon.setTextColor(accent());
        empty.addView(icon);
        TextView title = text(trulyEmpty ? "最初の探索ログを作ろう" : "一致する記録がありません", 16, true);
        title.setGravity(Gravity.CENTER);
        empty.addView(title, topMargin(8));
        TextView desc = text(trulyEmpty ? "上のフォームから暗号化して保存できます。" : "検索ワードやフィルターを変えてみてください。", 13, false);
        desc.setTextColor(muted());
        desc.setGravity(Gravity.CENTER);
        empty.addView(desc, topMargin(4));
        return empty;
    }

    private JSONArray load() {
        try {
            JSONArray result = new JSONArray(vault.loadEntries(prefs, KEY_ENTRIES));
            vaultReadError = false;
            return result;
        } catch (Exception e) {
            vaultReadError = true;
            return new JSONArray();
        }
    }

    private void persist(JSONArray all) throws Exception {
        if (vaultReadError) {
            throw new SecurityException("Vault integrity/read error: refusing to overwrite protected data");
        }
        vault.saveEntries(all.toString());
    }

    private JSONObject findById(JSONArray all, String id) {
        for (int i = 0; i < all.length(); i++) {
            JSONObject o = all.optJSONObject(i);
            if (o != null && id.equals(o.optString("id"))) return o;
        }
        return null;
    }

    private void requestEncryptedExport() {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(20), dp(8), dp(20), 0);
        EditText a = passwordEdit("パスフレーズ（8文字以上）");
        EditText b = passwordEdit("パスフレーズを再入力");
        box.addView(a, topMargin(6));
        box.addView(b, topMargin(10));

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("暗号化バックアップ")
                .setMessage("バックアップ専用のパスフレーズでAES-256-GCM暗号化します。PINとは別にできます。")
                .setView(box)
                .setNegativeButton("キャンセル", null)
                .setPositiveButton("書き出す", null)
                .create();
        dialog.setOnShowListener(x -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String p1 = a.getText().toString();
            if (p1.length() < 8) {
                toast("8文字以上にしてください");
                return;
            }
            if (!p1.equals(b.getText().toString())) {
                toast("パスフレーズが一致しません");
                return;
            }
            pendingBackupPassphrase = p1;
            Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            intent.setType("application/octet-stream");
            intent.putExtra(Intent.EXTRA_TITLE, "trailnote-backup.tnvault");
            startActivityForResult(intent, REQ_EXPORT_VAULT);
            dialog.dismiss();
        }));
        dialog.show();
    }

    private void requestEncryptedImport() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(intent, REQ_IMPORT_VAULT);
    }

    private void showImportPassphraseDialog(String raw) {
        EditText pass = passwordEdit("バックアップのパスフレーズ");
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(20), dp(8), dp(20), 0);
        box.addView(pass);

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("暗号化バックアップを復元")
                .setMessage("正しいパスフレーズを入力してください。")
                .setView(box)
                .setNegativeButton("キャンセル", null)
                .setPositiveButton("復元", null)
                .create();
        dialog.setOnShowListener(x -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            try {
                String plain = vault.decryptBackup(raw, pass.getText().toString());
                JSONArray parsed = new JSONArray(plain);
                persist(parsed);
                clearForm();
                render();
                dialog.dismiss();
                toast("暗号化バックアップを復元しました");
            } catch (Exception e) {
                toast("復元できません。パスフレーズまたはファイルを確認してください");
            }
        }));
        dialog.show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            pendingBackupPassphrase = null;
            return;
        }
        Uri uri = data.getData();
        if (requestCode == REQ_EXPORT_VAULT) {
            String passphrase = pendingBackupPassphrase;
            pendingBackupPassphrase = null;
            try (OutputStream out = getContentResolver().openOutputStream(uri)) {
                if (out == null) throw new IllegalStateException("出力先を開けません");
                String encrypted = vault.encryptBackup(load().toString(), passphrase);
                out.write(encrypted.getBytes(StandardCharsets.UTF_8));
                toast("暗号化バックアップを書き出しました");
            } catch (Exception e) {
                toast("書き出しに失敗しました");
            }
        } else if (requestCode == REQ_IMPORT_VAULT) {
            try (InputStream in = getContentResolver().openInputStream(uri)) {
                if (in == null) throw new IllegalStateException("ファイルを開けません");
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                byte[] chunk = new byte[8192];
                int n;
                while ((n = in.read(chunk)) != -1) {
                    if (buffer.size() + n > 10 * 1024 * 1024) {
                        throw new IllegalArgumentException("バックアップが大きすぎます");
                    }
                    buffer.write(chunk, 0, n);
                }
                showImportPassphraseDialog(buffer.toString(StandardCharsets.UTF_8.name()));
            } catch (Exception e) {
                toast("バックアップを読み込めません");
            }
        }
    }

    private View sectionHeader(String eyebrow, String title) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        TextView eye = text(eyebrow, 11, true);
        eye.setTextColor(accent());
        eye.setLetterSpacing(0.13f);
        box.addView(eye);
        TextView t = text(title, 20, true);
        box.addView(t, topMargin(2));
        return box;
    }

    private TextView fieldLabel(String label, boolean required) {
        TextView v = text(required ? label + "  *" : label, 12, true);
        v.setTextColor(required ? fg() : muted());
        return v;
    }

    private TextView text(String s, int sp, boolean bold) {
        TextView v = new TextView(this);
        v.setText(s);
        v.setTextColor(fg());
        v.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        v.setTypeface(Typeface.create("sans-serif", bold ? Typeface.BOLD : Typeface.NORMAL));
        return v;
    }

    private EditText edit(String hint, boolean multiline) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setHintTextColor(hintColor());
        e.setTextColor(fg());
        e.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        e.setSingleLine(!multiline);
        e.setSelectAllOnFocus(false);
        if (multiline) {
            e.setMinLines(4);
            e.setMaxLines(7);
            e.setGravity(Gravity.TOP | Gravity.START);
        }
        e.setPadding(dp(13), dp(11), dp(13), dp(11));
        e.setBackground(round(inputBg(), dp(12), dp(1), border()));
        return e;
    }

    private EditText pinEdit(String hint) {
        EditText e = edit(hint, false);
        e.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        e.setGravity(Gravity.CENTER);
        return e;
    }

    private EditText passwordEdit(String hint) {
        EditText e = edit(hint, false);
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        return e;
    }

    private CheckBox check(String label) {
        CheckBox c = new CheckBox(this);
        c.setText(label);
        c.setTextColor(fg());
        c.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        c.setButtonTintList(new ColorStateList(
                new int[][]{new int[]{android.R.attr.state_checked}, new int[]{}},
                new int[]{accent(), muted()}));
        return c;
    }

    private Button actionButton(String label, ButtonStyle style) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        b.setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
        b.setMinHeight(dp(48));
        b.setPadding(dp(12), dp(8), dp(12), dp(8));
        b.setStateListAnimator(null);
        switch (style) {
            case PRIMARY:
                b.setTextColor(Color.WHITE);
                b.setBackground(round(accent(), dp(12), 0, Color.TRANSPARENT));
                break;
            case DANGER_GHOST:
                b.setTextColor(danger());
                b.setBackground(round(dangerSoft(), dp(12), dp(1), dangerBorder()));
                break;
            default:
                b.setTextColor(fg());
                b.setBackground(round(surface2(), dp(12), dp(1), border()));
                break;
        }
        return b;
    }

    private Button miniButton(String label) {
        Button b = actionButton(label, ButtonStyle.SECONDARY);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        b.setMinHeight(dp(38));
        b.setPadding(dp(6), dp(4), dp(6), dp(4));
        return b;
    }

    private LinearLayout panel(int radius, int color, boolean elevated) {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setBackground(round(color, radius, dp(1), border()));
        if (elevated) l.setElevation(dp(2));
        return l;
    }

    private StatBlock statBlock(String label, String value, String caption) {
        LinearLayout card = panel(dp(16), cardBg(), true);
        card.setPadding(dp(12), dp(12), dp(12), dp(12));
        TextView labelView = text(label, 9, true);
        labelView.setTextColor(muted());
        labelView.setLetterSpacing(0.10f);
        card.addView(labelView);
        TextView valueView = text(value, 24, true);
        card.addView(valueView, topMargin(2));
        TextView captionView = text(caption, 11, false);
        captionView.setTextColor(muted());
        card.addView(captionView, topMargin(1));
        return new StatBlock(card, valueView);
    }

    private GradientDrawable round(int color, float radius, int strokeWidth, int strokeColor) {
        GradientDrawable gd = new GradientDrawable();
        gd.setColor(color);
        gd.setCornerRadius(radius);
        if (strokeWidth > 0) gd.setStroke(strokeWidth, strokeColor);
        return gd;
    }

    private LinearLayout.LayoutParams topMargin(int dpValue) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.topMargin = dp(dpValue);
        return p;
    }

    private LinearLayout.LayoutParams weight() {
        return new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
    }

    private LinearLayout.LayoutParams weightWithRight(int rightDp) {
        LinearLayout.LayoutParams p = weight();
        p.rightMargin = dp(rightDp);
        return p;
    }

    private LinearLayout.LayoutParams wrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private int dp(int value) {
        return (int) TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value, getResources().getDisplayMetrics());
    }

    private String format(long millis) {
        if (millis <= 0) return "日時不明";
        return new SimpleDateFormat("yyyy/MM/dd  HH:mm", Locale.JAPAN).format(new Date(millis));
    }

    private int bg() { return dark ? Color.rgb(12, 15, 17) : Color.rgb(244, 247, 245); }
    private int heroBg() { return dark ? Color.rgb(23, 29, 27) : Color.rgb(238, 246, 240); }
    private int cardBg() { return dark ? Color.rgb(24, 28, 30) : Color.WHITE; }
    private int selectedCardBg() { return dark ? Color.rgb(29, 36, 33) : Color.rgb(247, 252, 248); }
    private int inputBg() { return dark ? Color.rgb(18, 22, 24) : Color.rgb(249, 250, 249); }
    private int surface2() { return dark ? Color.rgb(34, 39, 41) : Color.rgb(244, 246, 245); }
    private int fg() { return dark ? Color.rgb(242, 245, 243) : Color.rgb(24, 31, 27); }
    private int secondaryText() { return dark ? Color.rgb(211, 216, 213) : Color.rgb(55, 64, 59); }
    private int muted() { return dark ? Color.rgb(154, 165, 159) : Color.rgb(103, 114, 108); }
    private int hintColor() { return dark ? Color.rgb(120, 130, 125) : Color.rgb(145, 154, 149); }
    private int border() { return dark ? Color.rgb(53, 61, 57) : Color.rgb(222, 229, 224); }
    private int accent() { return dark ? Color.rgb(101, 203, 132) : Color.rgb(28, 127, 69); }
    private int accentSoft() { return dark ? Color.rgb(28, 58, 39) : Color.rgb(229, 245, 235); }
    private int selectedAccent() { return dark ? Color.rgb(122, 181, 255) : Color.rgb(42, 105, 190); }
    private int selectedSoft() { return dark ? Color.rgb(28, 48, 70) : Color.rgb(232, 241, 252); }
    private int success() { return dark ? Color.rgb(111, 211, 144) : Color.rgb(31, 137, 75); }
    private int successSoft() { return dark ? Color.rgb(27, 55, 37) : Color.rgb(231, 247, 237); }
    private int danger() { return dark ? Color.rgb(255, 132, 132) : Color.rgb(184, 53, 53); }
    private int dangerSoft() { return dark ? Color.rgb(58, 31, 31) : Color.rgb(255, 244, 244); }
    private int dangerBorder() { return dark ? Color.rgb(105, 58, 58) : Color.rgb(240, 203, 203); }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }

    private enum ButtonStyle { PRIMARY, SECONDARY, DANGER_GHOST }

    private static final class StatBlock {
        final LinearLayout root;
        final TextView value;
        StatBlock(LinearLayout root, TextView value) {
            this.root = root;
            this.value = value;
        }
    }
}
