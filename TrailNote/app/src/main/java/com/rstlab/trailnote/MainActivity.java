package com.rstlab.trailnote;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
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
    private TextView statsView;
    private LinearLayout listContainer;
    private String selectedId;
    private boolean dark;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
        buildUi();
        render();
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(bg());

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18), dp(18), dp(18), dp(36));
        scroll.addView(root, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView h1 = text("TrailNote", 30, true);
        root.addView(h1);
        TextView sub = text("田舎・森・撮影スポットを、完全オフラインで残す探索ログ", 14, false);
        sub.setTextColor(muted());
        root.addView(sub, topMargin(4));

        statsView = text("", 15, true);
        root.addView(statsView, topMargin(16));

        root.addView(section("記録を追加 / 編集"), topMargin(24));
        titleInput = edit("タイトル（必須）", false);
        placeInput = edit("場所・エリア", false);
        tagsInput = edit("タグ  例: 森, 廃道, 夕景", false);
        memoInput = edit("撮影メモ・ルート・注意点", true);
        root.addView(titleInput, topMargin(8));
        root.addView(placeInput, topMargin(8));
        root.addView(tagsInput, topMargin(8));
        root.addView(memoInput, topMargin(8));

        LinearLayout checks = new LinearLayout(this);
        checks.setOrientation(LinearLayout.HORIZONTAL);
        favoriteInput = check("★ お気に入り");
        filmedInput = check("撮影済み");
        checks.addView(favoriteInput, weight());
        checks.addView(filmedInput, weight());
        root.addView(checks, topMargin(8));

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        Button newBtn = button("新規");
        Button saveBtn = button("保存");
        Button deleteBtn = button("削除");
        actions.addView(newBtn, weightWithRight(6));
        actions.addView(saveBtn, weightWithRight(6));
        actions.addView(deleteBtn, weight());
        root.addView(actions, topMargin(10));

        newBtn.setOnClickListener(v -> clearForm());
        saveBtn.setOnClickListener(v -> saveEntry());
        deleteBtn.setOnClickListener(v -> confirmDelete());

        root.addView(section("検索・一覧"), topMargin(26));
        searchInput = edit("タイトル / 場所 / タグ / メモを検索", false);
        root.addView(searchInput, topMargin(8));
        favoriteOnly = check("お気に入りだけ表示");
        root.addView(favoriteOnly, topMargin(4));

        searchInput.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) { render(); }
            @Override public void afterTextChanged(Editable s) {}
        });
        favoriteOnly.setOnCheckedChangeListener((buttonView, isChecked) -> render());

        LinearLayout backup = new LinearLayout(this);
        backup.setOrientation(LinearLayout.HORIZONTAL);
        Button exportBtn = button("JSONバックアップ");
        Button importBtn = button("復元");
        backup.addView(exportBtn, weightWithRight(6));
        backup.addView(importBtn, weight());
        root.addView(backup, topMargin(10));
        exportBtn.setOnClickListener(v -> exportJson());
        importBtn.setOnClickListener(v -> importJson());

        listContainer = new LinearLayout(this);
        listContainer.setOrientation(LinearLayout.VERTICAL);
        root.addView(listContainer, topMargin(12));

        TextView privacy = text("通信権限なし・位置情報権限なし・バックグラウンド処理なし", 12, false);
        privacy.setTextColor(muted());
        privacy.setGravity(Gravity.CENTER_HORIZONTAL);
        root.addView(privacy, topMargin(24));

        setContentView(scroll);
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
            render();
            toast(isNew ? "記録を追加しました" : "記録を更新しました");
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
                .setTitle("この記録を削除しますか？")
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
    }

    private void selectEntry(JSONObject o) {
        selectedId = o.optString("id", null);
        titleInput.setText(o.optString("title"));
        placeInput.setText(o.optString("place"));
        tagsInput.setText(o.optString("tags"));
        memoInput.setText(o.optString("memo"));
        favoriteInput.setChecked(o.optBoolean("favorite"));
        filmedInput.setChecked(o.optBoolean("filmed"));
        toast("編集対象に読み込みました");
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
            statsView.setText("記録 " + all.length() + "件   ★ " + fav + "   撮影済み " + filmed);

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
                listContainer.addView(card(o), topMargin(9));
                shown++;
            }
            if (shown == 0) {
                TextView empty = text(all.length() == 0 ? "まだ記録がありません。上から最初の探索ログを追加できます。"
                        : "条件に一致する記録がありません。", 14, false);
                empty.setTextColor(muted());
                listContainer.addView(empty, topMargin(12));
            }
        } catch (Exception e) {
            statsView.setText("データ読み込みエラー");
        }
    }

    private View card(JSONObject o) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(14), dp(12), dp(14), dp(12));
        GradientDrawable gd = new GradientDrawable();
        gd.setColor(cardBg());
        gd.setCornerRadius(dp(14));
        gd.setStroke(dp(1), border());
        card.setBackground(gd);

        String prefix = o.optBoolean("favorite") ? "★ " : "";
        TextView title = text(prefix + o.optString("title", "無題"), 18, true);
        card.addView(title);

        String place = o.optString("place");
        String tags = o.optString("tags");
        long created = o.optLong("createdAt", 0L);
        String meta = format(created);
        if (!place.isEmpty()) meta += "  ·  " + place;
        if (!tags.isEmpty()) meta += "\n# " + tags;
        TextView metaView = text(meta, 13, false);
        metaView.setTextColor(muted());
        card.addView(metaView, topMargin(4));

        String memo = o.optString("memo");
        if (!memo.isEmpty()) {
            TextView memoView = text(memo.length() > 180 ? memo.substring(0, 180) + "…" : memo, 14, false);
            card.addView(memoView, topMargin(7));
        }
        TextView state = text(o.optBoolean("filmed") ? "✓ 撮影済み" : "○ 未撮影", 12, true);
        state.setTextColor(o.optBoolean("filmed") ? Color.rgb(46, 125, 50) : muted());
        card.addView(state, topMargin(7));

        card.setOnClickListener(v -> selectEntry(o));
        return card;
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

    private TextView section(String s) {
        TextView v = text(s, 17, true);
        v.setTextColor(accent());
        return v;
    }

    private TextView text(String s, int sp, boolean bold) {
        TextView v = new TextView(this);
        v.setText(s);
        v.setTextColor(fg());
        v.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        if (bold) v.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return v;
    }

    private EditText edit(String hint, boolean multiline) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setHintTextColor(muted());
        e.setTextColor(fg());
        e.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        e.setSingleLine(!multiline);
        if (multiline) {
            e.setMinLines(3);
            e.setGravity(Gravity.TOP | Gravity.START);
        }
        e.setPadding(dp(12), dp(10), dp(12), dp(10));
        GradientDrawable gd = new GradientDrawable();
        gd.setColor(cardBg());
        gd.setCornerRadius(dp(10));
        gd.setStroke(dp(1), border());
        e.setBackground(gd);
        return e;
    }

    private CheckBox check(String label) {
        CheckBox c = new CheckBox(this);
        c.setText(label);
        c.setTextColor(fg());
        c.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        return c;
    }

    private Button button(String label) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        return b;
    }

    private LinearLayout.LayoutParams topMargin(int dp) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.topMargin = dp(dp);
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

    private int dp(int value) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value,
                getResources().getDisplayMetrics());
    }

    private String format(long millis) {
        if (millis <= 0) return "日時不明";
        return new SimpleDateFormat("yyyy/MM/dd HH:mm", Locale.JAPAN).format(new Date(millis));
    }

    private int bg() { return dark ? Color.rgb(17, 19, 21) : Color.rgb(247, 248, 250); }
    private int cardBg() { return dark ? Color.rgb(31, 34, 37) : Color.WHITE; }
    private int fg() { return dark ? Color.rgb(238, 240, 242) : Color.rgb(26, 29, 31); }
    private int muted() { return dark ? Color.rgb(174, 180, 184) : Color.rgb(97, 105, 110); }
    private int border() { return dark ? Color.rgb(63, 68, 72) : Color.rgb(220, 224, 227); }
    private int accent() { return dark ? Color.rgb(129, 199, 132) : Color.rgb(46, 125, 50); }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }
}
