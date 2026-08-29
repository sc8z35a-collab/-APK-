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
import android.text.TextWatcher;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
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
import java.util.Date;
import java.util.Locale;
import java.util.UUID;

public class MainActivity extends Activity {
    private static final String PREFS = "trailnote_prefs";
    private static final String KEY_ENTRIES = "entries";
    private static final int REQ_EXPORT = 201;
    private static final int REQ_IMPORT = 202;

    private SharedPreferences prefs;
    private EditText titleInput, placeInput, tagsInput, memoInput, searchInput;
    private CheckBox favoriteInput, filmedInput, favoriteOnly;
    private TextView totalValue, favoriteValue, filmedValue, resultsLabel, formModeLabel;
    private LinearLayout listContainer;
    private String selectedId;
    private boolean dark;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
        styleSystemBars();
        buildUi();
        render();
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

        root.addView(sectionHeader("LOG EDITOR", "探索ログを追加・編集"), topMargin(28));
        root.addView(buildEditorCard(), topMargin(10));

        root.addView(sectionHeader("LIBRARY", "記録を探す"), topMargin(28));
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
        TextView privacyTitle = text("LOCAL ONLY", 11, true);
        privacyTitle.setTextColor(accent());
        privacyTitle.setLetterSpacing(0.12f);
        privacyTitle.setGravity(Gravity.CENTER);
        privacyCard.addView(privacyTitle);
        TextView privacy = text("通信権限・位置情報権限・バックグラウンド処理なし", 12, false);
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
        LinearLayout.LayoutParams markParams = new LinearLayout.LayoutParams(dp(48), dp(48));
        top.addView(mark, markParams);

        LinearLayout titles = new LinearLayout(this);
        titles.setOrientation(LinearLayout.VERTICAL);
        TextView brand = text("TrailNote", 29, true);
        brand.setLetterSpacing(-0.02f);
        titles.addView(brand);
        TextView tagline = text("Explore. Capture. Remember.", 13, false);
        tagline.setTextColor(muted());
        titles.addView(tagline, topMargin(1));
        LinearLayout.LayoutParams titleParams = weight();
        titleParams.leftMargin = dp(14);
        top.addView(titles, titleParams);
        hero.addView(top);

        TextView lead = text("森・田舎・撮影スポットを、自分だけの探索ライブラリに。", 15, false);
        lead.setTextColor(fg());
        lead.setLineSpacing(0, 1.2f);
        hero.addView(lead, topMargin(18));

        TextView badge = text("●  OFFLINE FIRST", 11, true);
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

        Button saveBtn = actionButton("保存する", ButtonStyle.PRIMARY);
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

        searchInput.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) { render(); }
            @Override public void afterTextChanged(Editable s) {}
        });
        favoriteOnly.setOnCheckedChangeListener((buttonView, isChecked) -> render());

        TextView backupLabel = text("BACKUP", 11, true);
        backupLabel.setTextColor(muted());
        backupLabel.setLetterSpacing(0.10f);
        card.addView(backupLabel, topMargin(14));

        LinearLayout backup = new LinearLayout(this);
        backup.setOrientation(LinearLayout.HORIZONTAL);
        Button exportBtn = actionButton("JSON書き出し", ButtonStyle.SECONDARY);
        Button importBtn = actionButton("JSON復元", ButtonStyle.SECONDARY);
        backup.addView(exportBtn, weightWithRight(8));
        backup.addView(importBtn, weight());
        card.addView(backup, topMargin(6));
        exportBtn.setOnClickListener(v -> exportJson());
        importBtn.setOnClickListener(v -> importJson());
        return card;
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
            toast(isNew ? "探索ログを追加しました" : "探索ログを更新しました");
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
        toast("編集対象に読み込みました");
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
            for (int i = all.length() - 1; i >= 0; i--) {
                JSONObject o = all.optJSONObject(i);
                if (o == null) continue;
                if (favOnly && !o.optBoolean("favorite")) continue;
                String hay = (o.optString("title") + " " + o.optString("place") + " "
                        + o.optString("tags") + " " + o.optString("memo")).toLowerCase(Locale.ROOT);
                if (!q.isEmpty() && !hay.contains(q)) continue;
                listContainer.addView(entryCard(o), topMargin(10));
                shown++;
            }
            resultsLabel.setText(shown + "件");
            if (shown == 0) listContainer.addView(emptyState(all.length() == 0), topMargin(10));
        } catch (Exception e) {
            resultsLabel.setText("エラー");
        }
    }

    private View entryCard(JSONObject o) {
        boolean selected = selectedId != null && selectedId.equals(o.optString("id"));
        boolean filmed = o.optBoolean("filmed");
        boolean favorite = o.optBoolean("favorite");

        LinearLayout outer = new LinearLayout(this);
        outer.setOrientation(LinearLayout.HORIZONTAL);
        outer.setPadding(0, 0, 0, 0);
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

        TextView hint = text(selected ? "● 編集中" : "タップして編集", 11, true);
        hint.setTextColor(selected ? selectedAccent() : muted());
        content.addView(hint, topMargin(10));

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
        TextView desc = text(trulyEmpty ? "上のフォームから場所や撮影メモを保存できます。" : "検索ワードやフィルターを変えてみてください。", 13, false);
        desc.setTextColor(muted());
        desc.setGravity(Gravity.CENTER);
        empty.addView(desc, topMargin(4));
        return empty;
    }

    private JSONArray load() {
        try {
            return new JSONArray(prefs.getString(KEY_ENTRIES, "[]"));
        } catch (Exception e) {
            return new JSONArray();
        }
    }

    private void persist(JSONArray all) {
        prefs.edit().putString(KEY_ENTRIES, all.toString()).apply();
    }

    private JSONObject findById(JSONArray all, String id) {
        for (int i = 0; i < all.length(); i++) {
            JSONObject o = all.optJSONObject(i);
            if (o != null && id.equals(o.optString("id"))) return o;
        }
        return null;
    }

    private void exportJson() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.setType("application/json");
        intent.putExtra(Intent.EXTRA_TITLE, "trailnote-backup.json");
        startActivityForResult(intent, REQ_EXPORT);
    }

    private void importJson() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.setType("application/json");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(intent, REQ_IMPORT);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        if (requestCode == REQ_EXPORT) {
            try (OutputStream out = getContentResolver().openOutputStream(uri)) {
                if (out == null) throw new IllegalStateException("出力先を開けません");
                out.write(load().toString(2).getBytes(StandardCharsets.UTF_8));
                toast("バックアップを書き出しました");
            } catch (Exception e) {
                toast("書き出しに失敗しました: " + e.getMessage());
            }
        } else if (requestCode == REQ_IMPORT) {
            try (InputStream in = getContentResolver().openInputStream(uri)) {
                if (in == null) throw new IllegalStateException("ファイルを開けません");
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                byte[] chunk = new byte[8192];
                int n;
                while ((n = in.read(chunk)) != -1) buffer.write(chunk, 0, n);
                String raw = buffer.toString(StandardCharsets.UTF_8.name());
                JSONArray parsed = new JSONArray(raw);
                persist(parsed);
                clearForm();
                render();
                toast("バックアップを復元しました");
            } catch (Exception e) {
                toast("復元に失敗しました: JSON形式を確認してください");
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
        if (bold) v.setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
        else v.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
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
        return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private int dp(int value) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value,
                getResources().getDisplayMetrics());
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
