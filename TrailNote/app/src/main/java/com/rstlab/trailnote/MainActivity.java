package com.rstlab.trailnote;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.rstlab.trailnote.workspace.WorkspaceRepository;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** TrailNote v3 — offline exploration and filming operations workspace. */
public class MainActivity extends Activity {
    private static final int PAGE_HOME = 0;
    private static final int PAGE_EXPLORE = 1;
    private static final int PAGE_PLAN = 2;
    private static final int PAGE_MEDIA = 3;
    private static final int PAGE_ANALYZE = 4;
    private static final int PAGE_VAULT = 5;
    private static final int REQ_EXPORT = 401;
    private static final int REQ_IMPORT = 402;
    private static final long AUTO_LOCK_MS = 30_000L;
    private static final int MAX_IMPORT_BYTES = 10 * 1024 * 1024;

    private SecurityVault vault;
    private WorkspaceRepository repo;
    private LinearLayout pageRoot;
    private TextView headerTitle;
    private TextView headerSubtitle;
    private final Button[] navButtons = new Button[6];
    private int page = PAGE_HOME;
    private boolean dark;
    private boolean unlocked;
    private long backgroundAt;
    private String pendingExportPassphrase;
    private String pendingImportEnvelope;

    private interface StringCallback { void accept(String value); }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
        vault = new SecurityVault(this);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        styleSystemBars();
        if (vault.hasPin()) {
            unlocked = false;
            showLockScreen();
        } else {
            unlocked = true;
            openWorkspace(true);
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
        if (vault == null) return;
        if (backgroundAt > 0 && unlocked && vault.hasPin()
                && System.currentTimeMillis() - backgroundAt >= AUTO_LOCK_MS) {
            unlocked = false;
            showLockScreen();
            return;
        }
        if (unlocked) {
            try {
                vault.checkpointForeground();
            } catch (SecurityException e) {
                unlocked = false;
                showSecurityBlock(e.getMessage());
            }
        }
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (vault != null && vault.hasPin()) backgroundAt = System.currentTimeMillis();
    }

    @Override
    public boolean dispatchTouchEvent(MotionEvent event) {
        if ((event.getFlags() & MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0) {
            if (vault != null) vault.recordObscuredTouch();
            return false;
        }
        return super.dispatchTouchEvent(event);
    }

    private void openWorkspace(boolean firstRunPrompt) {
        try {
            vault.checkpointForeground();
            repo = new WorkspaceRepository(this, vault);
            repo.load();
            repo.seedStarterGearIfEmpty();
            buildShell();
            renderPage();
            if (firstRunPrompt && !vault.hasPin()) showFirstRunSecuritySetup();
        } catch (SecurityException e) {
            unlocked = false;
            showSecurityBlock(e.getMessage());
        } catch (Exception e) {
            showSecurityBlock("暗号化Workspaceを開けませんでした: " + safeMessage(e));
        }
    }

    private void styleSystemBars() {
        Window w = getWindow();
        w.setStatusBarColor(bg());
        w.setNavigationBarColor(bg());
        int flags = 0;
        if (!dark) flags |= View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        w.getDecorView().setSystemUiVisibility(flags);
    }

    private void showLockScreen() {
        vault.lockSession();
        LinearLayout root = column();
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(dp(28), dp(72), dp(28), dp(28));
        root.setBackgroundColor(bg());

        TextView mark = badge("TN", accent(), Color.WHITE);
        mark.setTextSize(TypedValue.COMPLEX_UNIT_SP, 24);
        root.addView(mark, size(dp(78), dp(78)));
        TextView title = text("TrailNote Operations Vault", 27, true);
        title.setGravity(Gravity.CENTER);
        root.addView(title, mt(22));
        TextView desc = text("探索・撮影計画・素材・ミッションを保護するSecurity Container Plant", 13, false);
        desc.setTextColor(muted());
        desc.setGravity(Gravity.CENTER);
        root.addView(desc, mt(8));

        EditText pin = input("6〜12桁 PIN", true);
        root.addView(pin, mt(24));
        TextView state = text("", 12, true);
        state.setTextColor(danger());
        state.setGravity(Gravity.CENTER);
        root.addView(state, mt(8));
        Button unlock = button("Vaultを解除", true);
        root.addView(unlock, mt(14));

        Runnable refresh = () -> {
            if (vault.isLockedOut()) {
                long sec = Math.max(1, (vault.lockoutUntil() - System.currentTimeMillis() + 999) / 1000);
                state.setText("認証ロックアウト: 約" + sec + "秒");
            } else if (vault.failedAttempts() > 0) {
                state.setText("PIN失敗 " + vault.failedAttempts() + " 回");
            } else state.setText("Triple Distribution Trust + AES-256-GCM");
        };
        refresh.run();
        unlock.setOnClickListener(v -> {
            try {
                if (vault.isLockedOut()) {
                    refresh.run();
                    return;
                }
                if (!vault.verifyPin(pin.getText().toString())) {
                    pin.setText("");
                    refresh.run();
                    toast("PINが違います");
                    return;
                }
                unlocked = true;
                backgroundAt = 0;
                openWorkspace(false);
            } catch (Exception e) {
                showSecurityBlock(safeMessage(e));
            }
        });
        setContentView(root);
    }

    private void showSecurityBlock(String reason) {
        if (vault != null) vault.lockSession();
        LinearLayout root = column();
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(dp(26), dp(70), dp(26), dp(30));
        root.setBackgroundColor(bg());
        TextView mark = badge("!", danger(), Color.WHITE);
        mark.setTextSize(TypedValue.COMPLEX_UNIT_SP, 28);
        root.addView(mark, size(dp(72), dp(72)));
        TextView title = text("SECURITY PLANT BLOCK", 22, true);
        title.setGravity(Gravity.CENTER);
        root.addView(title, mt(18));
        TextView info = text(reason == null ? "信頼境界が保護操作を拒否しました。" : reason, 13, false);
        info.setTextColor(muted());
        info.setGravity(Gravity.CENTER);
        root.addView(info, mt(10));
        if (vault != null) {
            TextView diag = text(vault.diagnosticsReport(), 11, false);
            diag.setTextColor(secondary());
            diag.setPadding(dp(14), dp(14), dp(14), dp(14));
            diag.setBackground(round(surface(), dp(14), border()));
            root.addView(diag, mt(20));
        }
        setContentView(root);
    }

    private void buildShell() {
        LinearLayout shell = column();
        shell.setBackgroundColor(bg());

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPadding(dp(16), dp(12), dp(16), dp(10));
        header.setBackgroundColor(surface());
        TextView mark = badge("TN", accent(), Color.WHITE);
        header.addView(mark, size(dp(42), dp(42)));
        LinearLayout titles = column();
        headerTitle = text("Operations", 20, true);
        headerSubtitle = text("TrailNote v3", 11, false);
        headerSubtitle.setTextColor(muted());
        titles.addView(headerTitle);
        titles.addView(headerSubtitle);
        LinearLayout.LayoutParams tp = weight();
        tp.leftMargin = dp(11);
        header.addView(titles, tp);
        TextView trust = badge("VAULT", accentSoft(), accent());
        trust.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        header.addView(trust, wrap());
        shell.addView(header, new LinearLayout.LayoutParams(-1, -2));

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        pageRoot = column();
        pageRoot.setPadding(dp(15), dp(15), dp(15), dp(34));
        scroll.addView(pageRoot, new ScrollView.LayoutParams(-1, -2));
        shell.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1f));

        LinearLayout nav = new LinearLayout(this);
        nav.setOrientation(LinearLayout.HORIZONTAL);
        nav.setPadding(dp(5), dp(6), dp(5), dp(8));
        nav.setBackgroundColor(surface());
        String[] names = {"HOME", "EXPLORE", "PLAN", "MEDIA", "ANALYZE", "VAULT"};
        for (int i = 0; i < names.length; i++) {
            final int target = i;
            Button b = new Button(this);
            b.setText(names[i]);
            b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 9);
            b.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
            b.setAllCaps(false);
            b.setPadding(dp(2), 0, dp(2), 0);
            b.setMinHeight(0);
            b.setMinimumHeight(0);
            b.setStateListAnimator(null);
            b.setOnClickListener(v -> {
                page = target;
                renderPage();
            });
            navButtons[i] = b;
            nav.addView(b, new LinearLayout.LayoutParams(0, dp(48), 1f));
        }
        shell.addView(nav, new LinearLayout.LayoutParams(-1, -2));
        setContentView(shell);
    }

    private void renderPage() {
        if (pageRoot == null || repo == null) return;
        try {
            vault.checkpointForeground();
            pageRoot.removeAllViews();
            String[] titles = {"Command Center", "Field Intelligence", "Production Planner", "Media Pipeline", "Operations Analytics", "Security Vault"};
            String[] subs = {"探索・撮影オペレーションを一画面で把握", "スポットと探索ログを管理", "撮影・ミッション・装備を統合", "素材を公開まで追跡", "進捗と撮影候補を分析", "Security Container Plant / Triple Trust"};
            headerTitle.setText(titles[page]);
            headerSubtitle.setText(subs[page]);
            for (int i = 0; i < navButtons.length; i++) styleNav(navButtons[i], i == page);
            switch (page) {
                case PAGE_HOME: renderHome(); break;
                case PAGE_EXPLORE: renderExplore(); break;
                case PAGE_PLAN: renderPlan(); break;
                case PAGE_MEDIA: renderMedia(); break;
                case PAGE_ANALYZE: renderAnalyze(); break;
                case PAGE_VAULT: renderVault(); break;
                default: renderHome();
            }
        } catch (SecurityException e) {
            unlocked = false;
            showSecurityBlock(e.getMessage());
        } catch (Exception e) {
            toast("表示に失敗: " + safeMessage(e));
        }
    }

    private void renderHome() throws Exception {
        pageRoot.addView(hero("TRAILNOTE v3", "Exploration Operations System", "探索候補から撮影・素材・公開までを、暗号化された1つのWorkspaceで管理します。"));

        LinearLayout stats1 = row();
        stats1.addView(stat("SPOTS", repo.count(WorkspaceRepository.SPOTS), "候補地"), weightMargin(6));
        stats1.addView(stat("PLANS", repo.count(WorkspaceRepository.PLANS), "撮影計画"), weightMargin(6));
        stats1.addView(stat("MEDIA", repo.count(WorkspaceRepository.ASSETS), "素材"), weight());
        pageRoot.addView(stats1, mt(12));
        LinearLayout stats2 = row();
        stats2.addView(stat("LOGS", repo.count(WorkspaceRepository.LOGS), "探索記録"), weightMargin(6));
        stats2.addView(stat("MISSIONS", repo.count(WorkspaceRepository.MISSIONS), "任務"), weightMargin(6));
        stats2.addView(stat("GEAR", repo.count(WorkspaceRepository.GEAR), "装備"), weight());
        pageRoot.addView(stats2, mt(7));

        pageRoot.addView(section("QUICK OPS", "今すぐ追加"), mt(24));
        LinearLayout quick1 = row();
        Button spot = button("＋ スポット", true);
        Button plan = button("＋ 撮影計画", false);
        quick1.addView(spot, weightMargin(7));
        quick1.addView(plan, weight());
        pageRoot.addView(quick1, mt(9));
        LinearLayout quick2 = row();
        Button mission = button("＋ ミッション", false);
        Button media = button("＋ 素材", false);
        quick2.addView(mission, weightMargin(7));
        quick2.addView(media, weight());
        pageRoot.addView(quick2, mt(7));
        spot.setOnClickListener(v -> showSpotDialog());
        plan.setOnClickListener(v -> showPlanDialog(null));
        mission.setOnClickListener(v -> showMissionDialog());
        media.setOnClickListener(v -> showAssetDialog());

        pageRoot.addView(section("NEXT TARGET", "撮影優先度エンジン"), mt(24));
        List<WorkspaceRepository.Candidate> ranked = repo.rankedCandidates();
        if (ranked.isEmpty()) {
            pageRoot.addView(empty("スポットを登録すると、撮影候補スコアを自動計算します。"), mt(9));
        } else {
            WorkspaceRepository.Candidate c = ranked.get(0);
            JSONObject s = c.spot;
            LinearLayout card = card();
            LinearLayout top = row();
            TextView name = text(s.optString("title", "無題スポット"), 19, true);
            top.addView(name, weight());
            top.addView(scoreBadge(c.score), wrap());
            card.addView(top);
            TextView meta = text(s.optString("area", "場所未設定") + " • " + s.optString("category", "未分類"), 12, false);
            meta.setTextColor(muted());
            card.addView(meta, mt(5));
            TextView why = text("優先度 " + s.optInt("priority", 3) + "/5  ｜ 画 " + s.optInt("rating", 3) + "/5  ｜ 新規性 " + s.optInt("novelty", 3) + "/5  ｜ 危険度 " + s.optInt("risk", 2) + "/5", 12, false);
            why.setTextColor(secondary());
            card.addView(why, mt(9));
            Button makePlan = button("このスポットの撮影計画を作る", true);
            card.addView(makePlan, mt(13));
            makePlan.setOnClickListener(v -> showPlanDialog(s));
            pageRoot.addView(card, mt(9));
        }

        pageRoot.addView(section("UNIFIED SEARCH", "Workspace全体を検索"), mt(24));
        LinearLayout searchCard = card();
        EditText search = input("場所・タグ・企画・素材名を検索", false);
        searchCard.addView(search);
        Button searchBtn = button("Workspace検索", false);
        searchCard.addView(searchBtn, mt(9));
        searchBtn.setOnClickListener(v -> showSearchResults(search.getText().toString()));
        pageRoot.addView(searchCard, mt(9));

        pageRoot.addView(section("PRODUCTION PULSE", "現在の進捗"), mt(24));
        pageRoot.addView(progressCard("撮影計画完了", repo.planCompletionPercent(), "DONEになった撮影計画"), mt(9));
        pageRoot.addView(progressCard("ミッション進捗", repo.missionAverageProgress(), "全ミッションの平均"), mt(7));
        pageRoot.addView(progressCard("装備準備", repo.gearReadyPercent(), "packedチェック率"), mt(7));
    }

    private void renderExplore() throws Exception {
        pageRoot.addView(hero("FIELD INTELLIGENCE", "Spot + Exploration Log", "現地候補を評価し、訪問記録と撮影価値を蓄積します。"));
        LinearLayout actions = row();
        Button addSpot = button("＋ スポット", true);
        Button addLog = button("＋ 探索ログ", false);
        actions.addView(addSpot, weightMargin(7));
        actions.addView(addLog, weight());
        pageRoot.addView(actions, mt(12));
        addSpot.setOnClickListener(v -> showSpotDialog());
        addLog.setOnClickListener(v -> showLogDialog(null));

        pageRoot.addView(section("SPOT RANKING", "撮影候補スコア順"), mt(24));
        List<WorkspaceRepository.Candidate> ranked = repo.rankedCandidates();
        if (ranked.isEmpty()) pageRoot.addView(empty("まだスポットがありません。"), mt(9));
        for (WorkspaceRepository.Candidate candidate : ranked) pageRoot.addView(spotCard(candidate), mt(8));

        pageRoot.addView(section("FIELD LOG", "最近の探索記録"), mt(24));
        List<JSONObject> logs = repo.recent(WorkspaceRepository.LOGS, 30);
        if (logs.isEmpty()) pageRoot.addView(empty("探索ログはまだありません。"), mt(9));
        for (JSONObject log : logs) pageRoot.addView(logCard(log), mt(8));
    }

    private View spotCard(WorkspaceRepository.Candidate candidate) {
        JSONObject s = candidate.spot;
        LinearLayout card = card();
        LinearLayout top = row();
        TextView title = text(s.optString("title", "無題スポット"), 18, true);
        top.addView(title, weight());
        top.addView(scoreBadge(candidate.score), wrap());
        card.addView(top);
        TextView meta = text(s.optString("area", "場所未設定") + "  •  " + s.optString("category", "未分類")
                + (s.optBoolean("filmed", false) ? "  •  撮影済み" : "  •  未撮影"), 12, false);
        meta.setTextColor(muted());
        card.addView(meta, mt(5));
        String tags = s.optString("tags", "");
        if (!tags.isEmpty()) {
            TextView tag = text("# " + tags.replace(",", "   # "), 11, true);
            tag.setTextColor(accent());
            card.addView(tag, mt(7));
        }
        TextView metrics = text("P" + s.optInt("priority", 3) + "  VIS" + s.optInt("rating", 3)
                + "  NOV" + s.optInt("novelty", 3) + "  ACCESS" + s.optInt("access", 3) + "  RISK" + s.optInt("risk", 2), 11, true);
        metrics.setTextColor(secondary());
        card.addView(metrics, mt(8));
        if (!s.optString("note", "").isEmpty()) {
            TextView note = text(s.optString("note"), 13, false);
            note.setTextColor(secondary());
            card.addView(note, mt(8));
        }
        if (s.has("lat") && s.has("lon")) {
            TextView coord = text("GPS memo  " + s.optString("lat") + ", " + s.optString("lon"), 11, false);
            coord.setTextColor(muted());
            card.addView(coord, mt(7));
        }
        LinearLayout buttons = row();
        Button fav = mini(s.optBoolean("favorite", false) ? "★" : "☆");
        Button filmed = mini(s.optBoolean("filmed", false) ? "未撮影へ" : "撮影済み");
        Button plan = mini("計画");
        Button del = mini("削除");
        buttons.addView(fav, weightMargin(5));
        buttons.addView(filmed, weightMargin(5));
        buttons.addView(plan, weightMargin(5));
        buttons.addView(del, weight());
        card.addView(buttons, mt(12));
        String id = s.optString("id");
        fav.setOnClickListener(v -> mutate(() -> repo.setBoolean(WorkspaceRepository.SPOTS, id, "favorite", !s.optBoolean("favorite", false))));
        filmed.setOnClickListener(v -> mutate(() -> repo.setBoolean(WorkspaceRepository.SPOTS, id, "filmed", !s.optBoolean("filmed", false))));
        plan.setOnClickListener(v -> showPlanDialog(s));
        del.setOnClickListener(v -> confirmDelete("スポット", () -> repo.delete(WorkspaceRepository.SPOTS, id)));
        return card;
    }

    private View logCard(JSONObject log) {
        LinearLayout card = card();
        LinearLayout top = row();
        TextView title = text(log.optString("title", "探索ログ"), 16, true);
        top.addView(title, weight());
        if (log.optBoolean("favorite", false)) top.addView(badge("★", accentSoft(), accent()), wrap());
        card.addView(top);
        TextView meta = text(log.optString("place", "場所未設定") + (log.optBoolean("filmed", false) ? " • 撮影済み" : " • 未撮影"), 11, false);
        meta.setTextColor(muted());
        card.addView(meta, mt(4));
        if (!log.optString("memo", "").isEmpty()) {
            TextView memo = text(log.optString("memo"), 12, false);
            memo.setTextColor(secondary());
            card.addView(memo, mt(7));
        }
        LinearLayout buttons = row();
        Button toggle = mini(log.optBoolean("filmed", false) ? "未撮影へ" : "撮影済み");
        Button del = mini("削除");
        buttons.addView(toggle, weightMargin(6));
        buttons.addView(del, weight());
        card.addView(buttons, mt(10));
        String id = log.optString("id");
        toggle.setOnClickListener(v -> mutate(() -> repo.setBoolean(WorkspaceRepository.LOGS, id, "filmed", !log.optBoolean("filmed", false))));
        del.setOnClickListener(v -> confirmDelete("探索ログ", () -> repo.delete(WorkspaceRepository.LOGS, id)));
        return card;
    }

    private void renderPlan() throws Exception {
        pageRoot.addView(hero("PRODUCTION PLANNER", "Plan + Mission + Gear", "撮影日の準備、達成すべき任務、持ち出し装備を一つの運用画面へ。"));
        LinearLayout pulse = row();
        pulse.addView(stat("PLAN", repo.planCompletionPercent(), "%完了"), weightMargin(6));
        pulse.addView(stat("MISSION", repo.missionAverageProgress(), "%進行"), weightMargin(6));
        pulse.addView(stat("GEAR", repo.gearReadyPercent(), "%準備"), weight());
        pageRoot.addView(pulse, mt(12));

        pageRoot.addView(section("SHOOTING PLAN", "撮影計画"), mt(24));
        Button addPlan = button("＋ 新しい撮影計画", true);
        pageRoot.addView(addPlan, mt(8));
        addPlan.setOnClickListener(v -> showPlanDialog(null));
        List<JSONObject> plans = repo.recent(WorkspaceRepository.PLANS, 40);
        if (plans.isEmpty()) pageRoot.addView(empty("撮影計画はまだありません。"), mt(8));
        for (JSONObject p : plans) pageRoot.addView(planCard(p), mt(8));

        pageRoot.addView(section("MISSIONS", "探索・制作ミッション"), mt(25));
        Button addMission = button("＋ ミッション追加", false);
        pageRoot.addView(addMission, mt(8));
        addMission.setOnClickListener(v -> showMissionDialog());
        List<JSONObject> missions = repo.recent(WorkspaceRepository.MISSIONS, 40);
        if (missions.isEmpty()) pageRoot.addView(empty("ミッションはありません。"), mt(8));
        for (JSONObject m : missions) pageRoot.addView(missionCard(m), mt(8));

        pageRoot.addView(section("FIELD LOADOUT", "持ち出し装備"), mt(25));
        Button addGear = button("＋ 装備を追加", false);
        pageRoot.addView(addGear, mt(8));
        addGear.setOnClickListener(v -> showGearDialog());
        JSONArray gear = repo.array(WorkspaceRepository.GEAR);
        for (int i = 0; i < gear.length(); i++) pageRoot.addView(gearCard(gear.getJSONObject(i)), mt(7));
    }

    private View planCard(JSONObject p) {
        LinearLayout card = card();
        LinearLayout top = row();
        top.addView(text(p.optString("title", "撮影計画"), 17, true), weight());
        top.addView(statusBadge(p.optString("status", "PLANNED")), wrap());
        card.addView(top);
        TextView meta = text(p.optString("date", "日付未設定") + " • " + p.optString("spot", "スポット未指定") + " • P" + p.optInt("priority", 3), 11, false);
        meta.setTextColor(muted());
        card.addView(meta, mt(5));
        addOptional(card, "SHOT", p.optString("shots", ""));
        addOptional(card, "NARRATION", p.optString("narration", ""));
        addOptional(card, "BGM", p.optString("bgm", ""));
        LinearLayout buttons = row();
        Button advance = mini("次の段階");
        Button del = mini("削除");
        buttons.addView(advance, weightMargin(6));
        buttons.addView(del, weight());
        card.addView(buttons, mt(10));
        String id = p.optString("id");
        advance.setOnClickListener(v -> mutate(() -> repo.setString(WorkspaceRepository.PLANS, id, "status", nextPlanStatus(p.optString("status", "PLANNED")))));
        del.setOnClickListener(v -> confirmDelete("撮影計画", () -> repo.delete(WorkspaceRepository.PLANS, id)));
        return card;
    }

    private View missionCard(JSONObject m) {
        LinearLayout card = card();
        LinearLayout top = row();
        top.addView(text(m.optString("title", "ミッション"), 16, true), weight());
        int progress = clamp(m.optInt("progress", 0), 0, 100);
        top.addView(badge(progress + "%", progress >= 100 ? successSoft() : accentSoft(), progress >= 100 ? success() : accent()), wrap());
        card.addView(top);
        TextView meta = text("期限 " + m.optString("deadline", "なし") + " • 優先度 " + m.optInt("priority", 3) + "/5", 11, false);
        meta.setTextColor(muted());
        card.addView(meta, mt(5));
        card.addView(progressBar(progress), mt(9));
        addOptional(card, "OBJECTIVE", m.optString("objective", ""));
        LinearLayout buttons = row();
        Button plus = mini("+25%");
        Button done = mini("完了");
        Button del = mini("削除");
        buttons.addView(plus, weightMargin(5));
        buttons.addView(done, weightMargin(5));
        buttons.addView(del, weight());
        card.addView(buttons, mt(10));
        String id = m.optString("id");
        plus.setOnClickListener(v -> mutate(() -> repo.setInt(WorkspaceRepository.MISSIONS, id, "progress", clamp(progress + 25, 0, 100))));
        done.setOnClickListener(v -> mutate(() -> repo.setInt(WorkspaceRepository.MISSIONS, id, "progress", 100)));
        del.setOnClickListener(v -> confirmDelete("ミッション", () -> repo.delete(WorkspaceRepository.MISSIONS, id)));
        return card;
    }

    private View gearCard(JSONObject g) {
        LinearLayout card = card();
        card.setPadding(dp(13), dp(12), dp(13), dp(12));
        LinearLayout line = row();
        CheckBox box = new CheckBox(this);
        box.setChecked(g.optBoolean("packed", false));
        box.setText(g.optString("name", "装備") + "  ×" + g.optInt("quantity", 1));
        box.setTextColor(fg());
        box.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        line.addView(box, weight());
        Button del = mini("×");
        line.addView(del, size(dp(52), dp(38)));
        card.addView(line);
        String id = g.optString("id");
        box.setOnCheckedChangeListener((b, checked) -> mutate(() -> repo.setBoolean(WorkspaceRepository.GEAR, id, "packed", checked)));
        del.setOnClickListener(v -> confirmDelete("装備", () -> repo.delete(WorkspaceRepository.GEAR, id)));
        return card;
    }

    private void renderMedia() throws Exception {
        pageRoot.addView(hero("MEDIA PIPELINE", "RAW → SELECT → EDIT → READY → PUBLISHED", "撮影素材を『撮った』で終わらせず、公開までの制作工程として追跡します。"));
        LinearLayout stats = row();
        stats.addView(stat("RAW", repo.countStatus(WorkspaceRepository.ASSETS, "stage", "RAW"), "素材"), weightMargin(6));
        stats.addView(stat("EDIT", repo.countStatus(WorkspaceRepository.ASSETS, "stage", "EDIT"), "編集中"), weightMargin(6));
        stats.addView(stat("PUBLISHED", repo.countStatus(WorkspaceRepository.ASSETS, "stage", "PUBLISHED"), "公開"), weight());
        pageRoot.addView(stats, mt(12));
        Button add = button("＋ 素材を登録", true);
        pageRoot.addView(add, mt(16));
        add.setOnClickListener(v -> showAssetDialog());
        pageRoot.addView(section("ASSET LIBRARY", "制作ステージを進める"), mt(24));
        List<JSONObject> assets = repo.recent(WorkspaceRepository.ASSETS, 80);
        if (assets.isEmpty()) pageRoot.addView(empty("素材はまだ登録されていません。ファイル本体ではなく、素材の管理メタデータをVault内に保持します。"), mt(8));
        for (JSONObject a : assets) pageRoot.addView(assetCard(a), mt(8));
    }

    private View assetCard(JSONObject a) {
        LinearLayout card = card();
        LinearLayout top = row();
        top.addView(text(a.optString("name", "素材"), 17, true), weight());
        top.addView(statusBadge(a.optString("stage", "RAW")), wrap());
        card.addView(top);
        TextView meta = text(a.optString("type", "VIDEO") + " • " + a.optString("spot", "場所未指定")
                + (a.optString("duration", "").isEmpty() ? "" : " • " + a.optString("duration")), 11, false);
        meta.setTextColor(muted());
        card.addView(meta, mt(5));
        addOptional(card, "REF", a.optString("reference", ""));
        addOptional(card, "NOTE", a.optString("note", ""));
        LinearLayout buttons = row();
        Button next = mini("次工程");
        Button del = mini("削除");
        buttons.addView(next, weightMargin(6));
        buttons.addView(del, weight());
        card.addView(buttons, mt(10));
        String id = a.optString("id");
        next.setOnClickListener(v -> mutate(() -> repo.setString(WorkspaceRepository.ASSETS, id, "stage", nextMediaStage(a.optString("stage", "RAW")))));
        del.setOnClickListener(v -> confirmDelete("素材", () -> repo.delete(WorkspaceRepository.ASSETS, id)));
        return card;
    }

    private void renderAnalyze() throws Exception {
        pageRoot.addView(hero("OPERATIONS ANALYTICS", "Offline Intelligence", "登録件数だけでなく、撮影準備・制作・候補地の偏りを可視化します。"));
        JSONObject s = repo.summaryJson();
        int operational = (s.optInt("planCompletion") + s.optInt("missionProgress") + s.optInt("mediaPublished") + s.optInt("gearReady")) / 4;
        LinearLayout score = card();
        TextView label = text("OPERATIONAL READINESS", 11, true);
        label.setTextColor(muted());
        score.addView(label);
        TextView big = text(operational + " / 100", 36, true);
        big.setTextColor(operational >= 75 ? success() : accent());
        score.addView(big, mt(5));
        score.addView(progressBar(operational), mt(8));
        pageRoot.addView(score, mt(12));

        pageRoot.addView(section("PIPELINE HEALTH", "主要KPI"), mt(24));
        pageRoot.addView(progressCard("撮影計画完了", repo.planCompletionPercent(), "撮影計画のDONE比率"), mt(8));
        pageRoot.addView(progressCard("ミッション平均", repo.missionAverageProgress(), "目標達成率"), mt(7));
        pageRoot.addView(progressCard("公開素材", repo.mediaPublishedPercent(), "PUBLISHED比率"), mt(7));
        pageRoot.addView(progressCard("装備準備", repo.gearReadyPercent(), "持ち出し準備率"), mt(7));

        pageRoot.addView(section("CATEGORY MAP", "スポット構成"), mt(24));
        Map<String, Integer> categories = repo.categoryCounts();
        if (categories.isEmpty()) pageRoot.addView(empty("スポットカテゴリがまだありません。"), mt(8));
        for (Map.Entry<String, Integer> e : categories.entrySet()) {
            LinearLayout line = card();
            line.setOrientation(LinearLayout.HORIZONTAL);
            line.addView(text(e.getKey(), 14, true), weight());
            line.addView(badge(String.valueOf(e.getValue()), accentSoft(), accent()), wrap());
            pageRoot.addView(line, mt(6));
        }

        pageRoot.addView(section("TOP TARGETS", "撮影優先順位 Top 5"), mt(24));
        List<WorkspaceRepository.Candidate> ranked = repo.rankedCandidates();
        int limit = Math.min(5, ranked.size());
        if (limit == 0) pageRoot.addView(empty("分析対象のスポットがありません。"), mt(8));
        for (int i = 0; i < limit; i++) {
            WorkspaceRepository.Candidate c = ranked.get(i);
            LinearLayout line = card();
            line.setOrientation(LinearLayout.HORIZONTAL);
            TextView rank = badge("#" + (i + 1), surface2(), secondary());
            line.addView(rank, size(dp(44), dp(38)));
            LinearLayout info = column();
            info.addView(text(c.spot.optString("title", "無題"), 14, true));
            TextView sub = text(c.spot.optString("area", "") + " • " + c.spot.optString("category", "未分類"), 10, false);
            sub.setTextColor(muted());
            info.addView(sub);
            LinearLayout.LayoutParams ip = weight(); ip.leftMargin = dp(10);
            line.addView(info, ip);
            line.addView(scoreBadge(c.score), wrap());
            pageRoot.addView(line, mt(6));
        }

        pageRoot.addView(section("VAULT SCALE", "暗号化Workspace規模"), mt(24));
        LinearLayout scale = card();
        scale.addView(text("Schema v3 / " + repo.totalObjects() + " operational objects", 15, true));
        TextView note = text("ログ・スポット・計画・ミッション・素材・装備を1つの認証付き暗号化Workspaceとして保存。", 12, false);
        note.setTextColor(muted());
        scale.addView(note, mt(6));
        pageRoot.addView(scale, mt(8));
    }

    private void renderVault() throws Exception {
        pageRoot.addView(hero("SECURITY VAULT", "Security Container Plant", "アプリ本体の大型化後も、すべてのWorkspaceデータは既存の暗号化・RASP・Triple Distribution Trust境界を通過します。"));
        LinearLayout status = card();
        LinearLayout top = row();
        top.addView(text("Runtime Security", 18, true), weight());
        top.addView(badge(vault.riskLevel() + " " + vault.riskScore(), vault.riskScore() >= 70 ? dangerSoft() : successSoft(), vault.riskScore() >= 70 ? danger() : success()), wrap());
        status.addView(top);
        TextView summary = text(vault.securitySummary(), 12, false);
        summary.setTextColor(secondary());
        status.addView(summary, mt(8));
        TextView objects = text("Encrypted workspace objects: " + repo.totalObjects(), 12, true);
        objects.setTextColor(accent());
        status.addView(objects, mt(9));
        pageRoot.addView(status, mt(12));

        pageRoot.addView(section("ACCESS", "認証とセッション"), mt(24));
        LinearLayout row = row();
        Button pin = button(vault.hasPin() ? "PIN変更" : "PIN設定", false);
        Button lock = button("今すぐロック", true);
        row.addView(pin, weightMargin(7));
        row.addView(lock, weight());
        pageRoot.addView(row, mt(8));
        pin.setOnClickListener(v -> showSetPinDialog());
        lock.setOnClickListener(v -> {
            if (!vault.hasPin()) showSetPinDialog();
            else { unlocked = false; showLockScreen(); }
        });

        pageRoot.addView(section("ENCRYPTED BACKUP", ".tnvault Workspace export/import"), mt(24));
        LinearLayout backup = row();
        Button export = button("暗号化Export", false);
        Button imp = button("暗号化Import", false);
        backup.addView(export, weightMargin(7));
        backup.addView(imp, weight());
        pageRoot.addView(backup, mt(8));
        export.setOnClickListener(v -> startExport());
        imp.setOnClickListener(v -> startImport());

        pageRoot.addView(section("DIAGNOSTICS", "サニタイズ済みセキュリティー状態"), mt(24));
        TextView diag = text(vault.diagnosticsReport(), 11, false);
        diag.setTextColor(secondary());
        diag.setPadding(dp(14), dp(14), dp(14), dp(14));
        diag.setBackground(round(surface(), dp(14), border()));
        pageRoot.addView(diag, mt(8));
    }

    private void showSpotDialog() {
        LinearLayout box = form();
        EditText title = labeled(box, "スポット名", "例: 山間の旧道入口", false);
        EditText area = labeled(box, "エリア", "市町村・地区・山域", false);
        EditText category = labeled(box, "カテゴリ", "森 / 集落 / 川 / 廃道 / 山 / 海 など", false);
        EditText tags = labeled(box, "タグ", "夕景, 自転車, 静寂", false);
        EditText priority = labeled(box, "優先度 1〜5", "3", true);
        EditText rating = labeled(box, "画の強さ 1〜5", "3", true);
        EditText novelty = labeled(box, "新規性 1〜5", "3", true);
        EditText access = labeled(box, "アクセス性 1〜5", "3", true);
        EditText risk = labeled(box, "危険度 1〜5", "2", true);
        EditText lat = labeled(box, "緯度メモ（任意）", "35.0000", false);
        EditText lon = labeled(box, "経度メモ（任意）", "137.0000", false);
        EditText note = labeled(box, "現地メモ", "光・音・道・時間帯・撮れ高など", false);
        showFormDialog("新しい探索スポット", box, () -> {
            if (title.getText().toString().trim().isEmpty()) throw new IllegalArgumentException("スポット名を入力してください");
            JSONObject o = new JSONObject();
            o.put("title", title.getText().toString().trim());
            o.put("area", area.getText().toString().trim());
            o.put("category", category.getText().toString().trim());
            o.put("tags", tags.getText().toString().trim());
            o.put("priority", number(priority, 3));
            o.put("rating", number(rating, 3));
            o.put("novelty", number(novelty, 3));
            o.put("access", number(access, 3));
            o.put("risk", number(risk, 2));
            o.put("filmed", false);
            o.put("favorite", false);
            if (!lat.getText().toString().trim().isEmpty()) o.put("lat", lat.getText().toString().trim());
            if (!lon.getText().toString().trim().isEmpty()) o.put("lon", lon.getText().toString().trim());
            o.put("note", note.getText().toString().trim());
            repo.add(WorkspaceRepository.SPOTS, o);
        });
    }

    private void showLogDialog(JSONObject spot) {
        LinearLayout box = form();
        EditText title = labeled(box, "ログタイトル", spot == null ? "探索内容" : spot.optString("title"), false);
        EditText place = labeled(box, "場所", spot == null ? "エリア" : spot.optString("area"), false);
        EditText tags = labeled(box, "タグ", spot == null ? "" : spot.optString("tags"), false);
        EditText memo = labeled(box, "記録", "現地状況・発見・撮影メモ", false);
        CheckBox favorite = checkbox("お気に入り");
        CheckBox filmed = checkbox("撮影済み");
        box.addView(favorite, mt(8));
        box.addView(filmed);
        showFormDialog("探索ログ", box, () -> {
            JSONObject o = new JSONObject();
            o.put("title", title.getText().toString().trim().isEmpty() ? "探索ログ" : title.getText().toString().trim());
            o.put("place", place.getText().toString().trim());
            o.put("tags", tags.getText().toString().trim());
            o.put("memo", memo.getText().toString().trim());
            o.put("favorite", favorite.isChecked());
            o.put("filmed", filmed.isChecked());
            if (spot != null) o.put("spotId", spot.optString("id"));
            repo.add(WorkspaceRepository.LOGS, o);
        });
    }

    private void showPlanDialog(JSONObject spot) {
        LinearLayout box = form();
        EditText title = labeled(box, "企画・撮影名", spot == null ? "" : spot.optString("title") + " 撮影", false);
        EditText spotName = labeled(box, "スポット", spot == null ? "" : spot.optString("title"), false);
        EditText date = labeled(box, "予定日", new SimpleDateFormat("yyyy-MM-dd", Locale.JAPAN).format(new Date()), false);
        EditText priority = labeled(box, "優先度 1〜5", "3", true);
        EditText shots = labeled(box, "ショットリスト", "導入 / 歩行 / 引き / ディテール / 締め", false);
        EditText narration = labeled(box, "ナレーション案", "ゆっくり解説の要点", false);
        EditText bgm = labeled(box, "BGMムード", "静寂 / 不穏 / 爽快 / ノスタルジー", false);
        showFormDialog("撮影計画を作成", box, () -> {
            if (title.getText().toString().trim().isEmpty()) throw new IllegalArgumentException("撮影名を入力してください");
            JSONObject o = new JSONObject();
            o.put("title", title.getText().toString().trim());
            o.put("spot", spotName.getText().toString().trim());
            if (spot != null) o.put("spotId", spot.optString("id"));
            o.put("date", date.getText().toString().trim());
            o.put("priority", number(priority, 3));
            o.put("shots", shots.getText().toString().trim());
            o.put("narration", narration.getText().toString().trim());
            o.put("bgm", bgm.getText().toString().trim());
            o.put("status", "PLANNED");
            repo.add(WorkspaceRepository.PLANS, o);
        });
    }

    private void showMissionDialog() {
        LinearLayout box = form();
        EditText title = labeled(box, "ミッション", "例: 川沿いルートの撮影候補を3箇所調査", false);
        EditText deadline = labeled(box, "期限", "yyyy-MM-dd または任意", false);
        EditText priority = labeled(box, "優先度 1〜5", "3", true);
        EditText objective = labeled(box, "完了条件", "何を達成したら100%か", false);
        showFormDialog("ミッション追加", box, () -> {
            if (title.getText().toString().trim().isEmpty()) throw new IllegalArgumentException("ミッション名を入力してください");
            JSONObject o = new JSONObject();
            o.put("title", title.getText().toString().trim());
            o.put("deadline", deadline.getText().toString().trim());
            o.put("priority", number(priority, 3));
            o.put("objective", objective.getText().toString().trim());
            o.put("progress", 0);
            repo.add(WorkspaceRepository.MISSIONS, o);
        });
    }

    private void showAssetDialog() {
        LinearLayout box = form();
        EditText name = labeled(box, "素材名", "例: 林道A7IV_001", false);
        EditText type = labeled(box, "種類", "VIDEO / AUDIO / PHOTO / NARRATION", false);
        EditText spot = labeled(box, "撮影スポット", "場所・企画", false);
        EditText duration = labeled(box, "尺・長さ", "02:35 など", false);
        EditText reference = labeled(box, "ファイル参照メモ", "SD1/DCIM/... 等（ファイル本体は保存しません）", false);
        EditText note = labeled(box, "制作メモ", "採用候補・編集指示など", false);
        showFormDialog("素材を登録", box, () -> {
            if (name.getText().toString().trim().isEmpty()) throw new IllegalArgumentException("素材名を入力してください");
            JSONObject o = new JSONObject();
            o.put("name", name.getText().toString().trim());
            o.put("type", type.getText().toString().trim().isEmpty() ? "VIDEO" : type.getText().toString().trim().toUpperCase(Locale.ROOT));
            o.put("spot", spot.getText().toString().trim());
            o.put("duration", duration.getText().toString().trim());
            o.put("reference", reference.getText().toString().trim());
            o.put("note", note.getText().toString().trim());
            o.put("stage", "RAW");
            repo.add(WorkspaceRepository.ASSETS, o);
        });
    }

    private void showGearDialog() {
        LinearLayout box = form();
        EditText name = labeled(box, "装備名", "例: NDフィルター", false);
        EditText qty = labeled(box, "数量", "1", true);
        showFormDialog("装備を追加", box, () -> {
            if (name.getText().toString().trim().isEmpty()) throw new IllegalArgumentException("装備名を入力してください");
            JSONObject o = new JSONObject();
            o.put("name", name.getText().toString().trim());
            o.put("quantity", Math.max(1, number(qty, 1)));
            o.put("packed", false);
            repo.add(WorkspaceRepository.GEAR, o);
        });
    }

    private interface ThrowingAction { void run() throws Exception; }

    private void showFormDialog(String title, LinearLayout box, ThrowingAction action) {
        ScrollView scroll = new ScrollView(this);
        scroll.addView(box);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(title)
                .setView(scroll)
                .setNegativeButton("キャンセル", null)
                .setPositiveButton("保存", null)
                .create();
        dialog.setOnShowListener(x -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            try {
                action.run();
                dialog.dismiss();
                renderPage();
                toast("保存しました");
            } catch (Exception e) {
                toast(safeMessage(e));
            }
        }));
        dialog.show();
    }

    private void showSearchResults(String query) {
        try {
            List<WorkspaceRepository.SearchHit> hits = repo.search(query);
            LinearLayout box = form();
            if (hits.isEmpty()) box.addView(text("一致するデータはありません。", 13, false));
            for (WorkspaceRepository.SearchHit h : hits) {
                LinearLayout line = card();
                line.addView(badge(h.type, surface2(), accent()));
                line.addView(text(h.title, 15, true), mt(7));
                TextView sub = text(h.subtitle, 11, false);
                sub.setTextColor(muted());
                line.addView(sub, mt(3));
                box.addView(line, mt(6));
            }
            ScrollView scroll = new ScrollView(this); scroll.addView(box);
            new AlertDialog.Builder(this).setTitle("Workspace検索 • " + hits.size() + "件").setView(scroll).setPositiveButton("閉じる", null).show();
        } catch (Exception e) {
            toast("検索失敗: " + safeMessage(e));
        }
    }

    private void showFirstRunSecuritySetup() {
        new AlertDialog.Builder(this)
                .setTitle("TrailNote Vault")
                .setMessage("v3 WorkspaceはAndroid Keystoreで暗号化されています。PINを設定すると、PIN由来鍵との二重鍵保護と自動ロックも有効になります。")
                .setNegativeButton("あとで", null)
                .setPositiveButton("PIN設定", (d, w) -> showSetPinDialog())
                .show();
    }

    private void showSetPinDialog() {
        boolean changing = vault.hasPin();
        LinearLayout box = form();
        EditText current = null;
        if (changing) current = labeled(box, "現在のPIN", "6〜12桁", true);
        EditText next = labeled(box, "新しいPIN", "6〜12桁", true);
        EditText confirm = labeled(box, "確認", "もう一度入力", true);
        final EditText currentFinal = current;
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle(changing ? "PIN変更" : "PIN設定")
                .setView(box).setNegativeButton("キャンセル", null).setPositiveButton("保存", null).create();
        dialog.setOnShowListener(x -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            try {
                if (changing && !vault.verifyPin(currentFinal.getText().toString())) { toast("現在のPINが違います"); return; }
                String a = next.getText().toString();
                if (!a.equals(confirm.getText().toString())) { toast("PINが一致しません"); return; }
                vault.setPin(a);
                dialog.dismiss();
                renderPage();
                toast("PINを更新しました");
            } catch (Exception e) { toast(safeMessage(e)); }
        }));
        dialog.show();
    }

    private void startExport() {
        askPassphrase("暗号化Export", true, pass -> {
            pendingExportPassphrase = pass;
            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("application/octet-stream");
            i.putExtra(Intent.EXTRA_TITLE, "TrailNote-v3-" + new SimpleDateFormat("yyyyMMdd-HHmm", Locale.JAPAN).format(new Date()) + ".tnvault");
            startActivityForResult(i, REQ_EXPORT);
        });
    }

    private void startImport() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        startActivityForResult(i, REQ_IMPORT);
    }

    private void askPassphrase(String title, boolean confirm, StringCallback callback) {
        LinearLayout box = form();
        EditText p1 = labeled(box, "バックアップ用パスフレーズ", "8文字以上", false);
        p1.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        EditText p2 = null;
        if (confirm) {
            p2 = labeled(box, "確認", "もう一度入力", false);
            p2.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        }
        final EditText p2Final = p2;
        AlertDialog d = new AlertDialog.Builder(this).setTitle(title).setView(box)
                .setNegativeButton("キャンセル", null).setPositiveButton("続行", null).create();
        d.setOnShowListener(x -> d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String value = p1.getText().toString();
            if (value.length() < 8) { toast("8文字以上にしてください"); return; }
            if (p2Final != null && !value.equals(p2Final.getText().toString())) { toast("一致しません"); return; }
            d.dismiss(); callback.accept(value);
        }));
        d.show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        if (requestCode == REQ_EXPORT) {
            try {
                if (pendingExportPassphrase == null) return;
                String envelope = vault.encryptBackup(repo.toJson(), pendingExportPassphrase);
                try (OutputStream out = getContentResolver().openOutputStream(uri, "w")) {
                    if (out == null) throw new IllegalStateException("出力先を開けません");
                    out.write(envelope.getBytes(StandardCharsets.UTF_8));
                }
                toast("暗号化Workspaceを書き出しました");
            } catch (Exception e) { toast("Export失敗: " + safeMessage(e)); }
            finally { pendingExportPassphrase = null; }
        } else if (requestCode == REQ_IMPORT) {
            try {
                pendingImportEnvelope = readUri(uri);
                askPassphrase("暗号化Import", false, pass -> {
                    try {
                        String json = vault.decryptBackup(pendingImportEnvelope, pass);
                        repo.replaceJson(json);
                        pendingImportEnvelope = null;
                        renderPage();
                        toast("Workspaceを復元しました");
                    } catch (Exception e) { toast("復元失敗: " + safeMessage(e)); }
                });
            } catch (Exception e) { toast("Import読込失敗: " + safeMessage(e)); }
        }
    }

    private String readUri(Uri uri) throws Exception {
        try (InputStream in = getContentResolver().openInputStream(uri); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            if (in == null) throw new IllegalStateException("入力を開けません");
            byte[] buf = new byte[8192];
            int n, total = 0;
            while ((n = in.read(buf)) != -1) {
                total += n;
                if (total > MAX_IMPORT_BYTES) throw new IllegalArgumentException("10MiBを超えるバックアップは拒否しました");
                out.write(buf, 0, n);
            }
            return out.toString(StandardCharsets.UTF_8.name());
        }
    }

    private void confirmDelete(String label, ThrowingAction action) {
        new AlertDialog.Builder(this).setTitle(label + "を削除")
                .setMessage("この操作は取り消せません。")
                .setNegativeButton("キャンセル", null)
                .setPositiveButton("削除", (d, w) -> mutate(action))
                .show();
    }

    private void mutate(ThrowingAction action) {
        try { action.run(); renderPage(); }
        catch (Exception e) { toast(safeMessage(e)); }
    }

    private LinearLayout hero(String eyebrow, String title, String description) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(18), dp(18), dp(18), dp(18));
        card.setBackground(round(heroBg(), dp(20), border()));
        TextView e = text(eyebrow, 10, true); e.setTextColor(accent()); e.setLetterSpacing(0.12f); card.addView(e);
        card.addView(text(title, 25, true), mt(6));
        TextView d = text(description, 13, false); d.setTextColor(secondary()); d.setLineSpacing(0, 1.18f); card.addView(d, mt(8));
        return card;
    }

    private LinearLayout section(String eyebrow, String title) {
        LinearLayout box = column();
        TextView e = text(eyebrow, 9, true); e.setTextColor(accent()); e.setLetterSpacing(0.13f); box.addView(e);
        box.addView(text(title, 19, true), mt(3));
        return box;
    }

    private LinearLayout card() {
        LinearLayout c = column();
        c.setPadding(dp(15), dp(14), dp(15), dp(14));
        c.setBackground(round(surface(), dp(16), border()));
        c.setElevation(dp(1));
        return c;
    }

    private View stat(String eyebrow, int value, String unit) {
        LinearLayout c = card(); c.setPadding(dp(11), dp(11), dp(11), dp(11));
        TextView e = text(eyebrow, 9, true); e.setTextColor(muted()); c.addView(e);
        TextView v = text(String.valueOf(value), 23, true); v.setTextColor(accent()); c.addView(v, mt(3));
        TextView u = text(unit, 10, false); u.setTextColor(muted()); c.addView(u);
        return c;
    }

    private View progressCard(String title, int progress, String subtitle) {
        LinearLayout c = card();
        LinearLayout top = row(); top.addView(text(title, 14, true), weight()); top.addView(badge(progress + "%", accentSoft(), accent()), wrap()); c.addView(top);
        TextView sub = text(subtitle, 10, false); sub.setTextColor(muted()); c.addView(sub, mt(3));
        c.addView(progressBar(progress), mt(9));
        return c;
    }

    private ProgressBar progressBar(int progress) {
        ProgressBar p = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        p.setMax(100); p.setProgress(clamp(progress, 0, 100)); p.setMinimumHeight(dp(8));
        return p;
    }

    private TextView scoreBadge(int score) {
        return badge(score + "/100", score >= 75 ? successSoft() : score >= 45 ? accentSoft() : dangerSoft(), score >= 75 ? success() : score >= 45 ? accent() : danger());
    }

    private TextView statusBadge(String status) {
        String s = status == null ? "" : status.toUpperCase(Locale.ROOT);
        boolean done = "DONE".equals(s) || "PUBLISHED".equals(s) || "READY".equals(s);
        return badge(s.isEmpty() ? "STATE" : s, done ? successSoft() : accentSoft(), done ? success() : accent());
    }

    private TextView badge(String value, int bg, int fg) {
        TextView t = text(value, 11, true);
        t.setTextColor(fg); t.setGravity(Gravity.CENTER); t.setPadding(dp(10), dp(6), dp(10), dp(6));
        t.setBackground(round(bg, dp(18), Color.TRANSPARENT));
        return t;
    }

    private View empty(String message) {
        LinearLayout c = card();
        TextView t = text(message, 12, false); t.setTextColor(muted()); t.setGravity(Gravity.CENTER); c.addView(t);
        return c;
    }

    private void addOptional(LinearLayout card, String label, String value) {
        if (value == null || value.trim().isEmpty()) return;
        TextView t = text(label + "  " + value, 11, false); t.setTextColor(secondary()); card.addView(t, mt(7));
    }

    private LinearLayout form() {
        LinearLayout box = column(); box.setPadding(dp(20), dp(4), dp(20), dp(12)); return box;
    }

    private EditText labeled(LinearLayout box, String label, String hint, boolean number) {
        TextView l = text(label, 11, true); l.setTextColor(muted()); box.addView(l, mt(10));
        EditText e = input(hint, number); box.addView(e, mt(4)); return e;
    }

    private EditText input(String hint, boolean number) {
        EditText e = new EditText(this);
        e.setHint(hint); e.setHintTextColor(muted()); e.setTextColor(fg()); e.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        e.setSingleLine(false); e.setPadding(dp(12), dp(10), dp(12), dp(10)); e.setBackground(round(surface2(), dp(12), border()));
        if (number) e.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        return e;
    }

    private CheckBox checkbox(String label) {
        CheckBox b = new CheckBox(this); b.setText(label); b.setTextColor(fg()); b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13); return b;
    }

    private Button button(String label, boolean primary) {
        Button b = new Button(this); b.setText(label); b.setAllCaps(false); b.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12); b.setMinHeight(0); b.setMinimumHeight(0); b.setStateListAnimator(null);
        b.setTextColor(primary ? Color.WHITE : fg()); b.setBackground(round(primary ? accent() : surface2(), dp(13), primary ? Color.TRANSPARENT : border()));
        return b;
    }

    private Button mini(String label) {
        Button b = button(label, false); b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10); return b;
    }

    private void styleNav(Button b, boolean active) {
        b.setTextColor(active ? accent() : muted());
        b.setBackground(round(active ? accentSoft() : Color.TRANSPARENT, dp(13), Color.TRANSPARENT));
    }

    private TextView text(String value, float sp, boolean bold) {
        TextView t = new TextView(this); t.setText(value); t.setTextColor(fg()); t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        if (bold) t.setTypeface(Typeface.DEFAULT, Typeface.BOLD); return t;
    }

    private LinearLayout column() { LinearLayout l = new LinearLayout(this); l.setOrientation(LinearLayout.VERTICAL); return l; }
    private LinearLayout row() { LinearLayout l = new LinearLayout(this); l.setOrientation(LinearLayout.HORIZONTAL); l.setGravity(Gravity.CENTER_VERTICAL); return l; }
    private LinearLayout.LayoutParams weight() { return new LinearLayout.LayoutParams(0, -2, 1f); }
    private LinearLayout.LayoutParams weightMargin(int right) { LinearLayout.LayoutParams p = weight(); p.rightMargin = dp(right); return p; }
    private LinearLayout.LayoutParams wrap() { return new LinearLayout.LayoutParams(-2, -2); }
    private LinearLayout.LayoutParams mt(int top) { LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-1, -2); p.topMargin = dp(top); return p; }
    private LinearLayout.LayoutParams size(int w, int h) { return new LinearLayout.LayoutParams(w, h); }

    private GradientDrawable round(int color, int radius, int stroke) {
        GradientDrawable d = new GradientDrawable(); d.setColor(color); d.setCornerRadius(radius);
        if (stroke != Color.TRANSPARENT) d.setStroke(dp(1), stroke); return d;
    }

    private int number(EditText e, int fallback) {
        try { return clamp(Integer.parseInt(e.getText().toString().trim()), 1, 5); }
        catch (Exception ex) { return fallback; }
    }

    private static int clamp(int v, int min, int max) { return Math.max(min, Math.min(max, v)); }

    private static String nextPlanStatus(String s) {
        if ("PLANNED".equalsIgnoreCase(s)) return "READY";
        if ("READY".equalsIgnoreCase(s)) return "DONE";
        return "PLANNED";
    }

    private static String nextMediaStage(String s) {
        if ("RAW".equalsIgnoreCase(s)) return "SELECT";
        if ("SELECT".equalsIgnoreCase(s)) return "EDIT";
        if ("EDIT".equalsIgnoreCase(s)) return "READY";
        if ("READY".equalsIgnoreCase(s)) return "PUBLISHED";
        return "RAW";
    }

    private int dp(int v) { return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, getResources().getDisplayMetrics()); }
    private int bg() { return dark ? Color.rgb(13, 16, 18) : Color.rgb(246, 248, 250); }
    private int surface() { return dark ? Color.rgb(25, 29, 32) : Color.WHITE; }
    private int surface2() { return dark ? Color.rgb(35, 40, 44) : Color.rgb(239, 243, 246); }
    private int heroBg() { return dark ? Color.rgb(19, 34, 29) : Color.rgb(234, 246, 238); }
    private int fg() { return dark ? Color.rgb(241, 244, 242) : Color.rgb(27, 33, 30); }
    private int secondary() { return dark ? Color.rgb(190, 199, 194) : Color.rgb(78, 88, 83); }
    private int muted() { return dark ? Color.rgb(142, 153, 147) : Color.rgb(112, 124, 118); }
    private int border() { return dark ? Color.rgb(52, 59, 55) : Color.rgb(220, 227, 222); }
    private int accent() { return Color.rgb(42, 125, 72); }
    private int accentSoft() { return dark ? Color.rgb(33, 65, 45) : Color.rgb(224, 242, 230); }
    private int success() { return Color.rgb(36, 133, 78); }
    private int successSoft() { return dark ? Color.rgb(28, 66, 45) : Color.rgb(224, 244, 232); }
    private int danger() { return Color.rgb(190, 62, 62); }
    private int dangerSoft() { return dark ? Color.rgb(75, 35, 35) : Color.rgb(251, 231, 231); }

    private void toast(String message) { Toast.makeText(this, message, Toast.LENGTH_SHORT).show(); }
    private static String safeMessage(Throwable e) { return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage(); }
}
