package com.rstlab.trailnote.workspace.adaptive;

import org.json.JSONArray;
import org.json.JSONObject;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Offline input-response engine for TrailNote.
 *
 * It does not call a server or use INTERNET permission. It interprets user-entered
 * text with a deterministic semantic rulebook, enriches records, links workspace
 * objects and creates high-confidence follow-up operations.
 */
public final class AdaptiveOperationsCore {
    public static final String ENGINE_VERSION = "1.0.0";

    private static final String LOGS = "logs";
    private static final String SPOTS = "spots";
    private static final String PLANS = "plans";
    private static final String MISSIONS = "missions";
    private static final String ASSETS = "assets";
    private static final String GEAR = "gear";

    public static final class Result {
        public boolean changed;
        public int confidence;
        public int generatedPlans;
        public int generatedMissions;
        public int generatedGear;
        public final List<String> signals = new ArrayList<>();
        public final List<String> actions = new ArrayList<>();

        public int generatedTotal() {
            return generatedPlans + generatedMissions + generatedGear;
        }
    }

    private AdaptiveOperationsCore() {}

    public static boolean upgradeWorkspace(JSONObject root) throws Exception {
        if (ENGINE_VERSION.equals(root.optString("adaptiveEngineVersion"))) return false;
        String[] types = {SPOTS, LOGS, PLANS, MISSIONS, ASSETS, GEAR};
        for (String type : types) {
            JSONArray arr = root.optJSONArray(type);
            if (arr == null) continue;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject item = arr.optJSONObject(i);
                if (item != null) apply(type, item, root, false);
            }
        }
        root.put("adaptiveEngineVersion", ENGINE_VERSION);
        root.put("adaptiveUpgradedAt", System.currentTimeMillis());
        return true;
    }

    public static Result apply(String type, JSONObject item, JSONObject root, boolean allowGeneration) throws Exception {
        Result result = new Result();
        if (item == null || root == null) return result;

        String text = textOf(type, item);
        boolean manual = AdaptiveRulebook.containsAny(text, "#manual", "自動化しない", "自動対応しない");
        boolean forceAuto = AdaptiveRulebook.containsAny(text, "#auto", "#autopilot", "自動化して", "自動対応して");
        boolean forcePlan = AdaptiveRulebook.containsAny(text, "#plan", "撮影計画を作", "撮影プランを作");
        boolean forceScout = AdaptiveRulebook.containsAny(text, "#scout", "下見", "ロケハン", "事前調査");

        if (manual) {
            JSONObject adaptive = item.optJSONObject("adaptive");
            if (adaptive == null) adaptive = new JSONObject();
            adaptive.put("engine", ENGINE_VERSION);
            adaptive.put("mode", "MANUAL_OVERRIDE");
            adaptive.put("at", System.currentTimeMillis());
            item.put("adaptive", adaptive);
            result.changed = true;
            return result;
        }

        switch (type) {
            case SPOTS:
                adaptSpot(item, root, result, allowGeneration, forceAuto, forcePlan, forceScout);
                break;
            case LOGS:
                adaptLog(item, root, result, allowGeneration, forceAuto);
                break;
            case PLANS:
                adaptPlan(item, root, result, allowGeneration, forceAuto);
                break;
            case MISSIONS:
                adaptMission(item, result);
                break;
            case ASSETS:
                adaptAsset(item, root, result);
                break;
            case GEAR:
                adaptGear(item, result);
                break;
            default:
                return result;
        }

        JSONObject adaptive = item.optJSONObject("adaptive");
        if (adaptive == null) adaptive = new JSONObject();
        adaptive.put("engine", ENGINE_VERSION);
        adaptive.put("mode", forceAuto ? "FORCED_AUTOPILOT" : "SMART");
        adaptive.put("confidence", result.confidence);
        adaptive.put("signals", toArray(result.signals));
        adaptive.put("actions", toArray(result.actions));
        adaptive.put("generated", result.generatedTotal());
        adaptive.put("at", System.currentTimeMillis());
        item.put("adaptive", adaptive);
        item.put("updatedAt", System.currentTimeMillis());
        result.changed = true;
        return result;
    }

    private static void adaptSpot(JSONObject spot, JSONObject root, Result r, boolean allowGeneration,
                                  boolean forceAuto, boolean forcePlan, boolean forceScout) throws Exception {
        String text = textOf(SPOTS, spot);
        String category = spot.optString("category", "").trim();
        String inferredCategory = AdaptiveRulebook.inferCategory(text);
        if ((category.isEmpty() || "未分類".equals(category)) && !"未分類".equals(inferredCategory)) {
            spot.put("category", inferredCategory);
            category = inferredCategory;
            r.actions.add("カテゴリ自動分類: " + inferredCategory);
        }
        if (category.isEmpty()) category = inferredCategory;

        Set<String> tags = new LinkedHashSet<>(AdaptiveRulebook.splitTags(spot.optString("tags", "")));
        Set<String> inferredTags = AdaptiveRulebook.inferTags(text);
        int beforeTags = tags.size();
        tags.addAll(inferredTags);
        if (tags.size() != beforeTags) {
            spot.put("tags", AdaptiveRulebook.joinTags(tags));
            r.actions.add("意味タグを自動付与");
        }

        List<String> risks = AdaptiveRulebook.riskSignals(text);
        r.signals.addAll(risks);
        boolean restricted = AdaptiveRulebook.containsAny(text, "立入禁止", "進入禁止", "私有地", "封鎖", "no trespassing")
                && !AdaptiveRulebook.hasPermissionSignal(text);
        if (restricted) {
            spot.put("restrictedAccess", true);
            spot.put("risk", 5);
            spot.put("access", 1);
            r.actions.add("立入制限シグナル: 候補順位を強制抑制");
        }

        int risk = clamp(spot.optInt("risk", 2), 1, 5);
        int inferredRisk = 1 + Math.min(4, risks.size());
        if (AdaptiveRulebook.containsAny(text, "崖", "崩落", "熊", "増水", "洞窟", "立入禁止")) inferredRisk = Math.max(inferredRisk, 4);
        if (inferredRisk > risk) {
            risk = inferredRisk;
            spot.put("risk", risk);
            r.actions.add("危険度を入力内容から上方補正");
        }

        int access = clamp(spot.optInt("access", 3), 1, 5);
        if (AdaptiveRulebook.containsAny(text, "徒歩1時間", "長時間歩", "急斜面", "悪路", "倒木", "渡渉", "遠い", "圏外")) {
            int next = Math.min(access, 2);
            if (next != access) {
                access = next;
                spot.put("access", access);
                r.actions.add("アクセス性を現地条件から補正");
            }
        } else if (AdaptiveRulebook.containsAny(text, "駅近", "駐車場あり", "アクセス良好", "すぐ着く")) {
            int next = Math.max(access, 4);
            if (next != access) {
                access = next;
                spot.put("access", access);
                r.actions.add("アクセス性を上方補正");
            }
        }

        int priority = clamp(spot.optInt("priority", 3), 1, 5);
        if (AdaptiveRulebook.containsAny(text, "#urgent", "最優先", "絶対撮る", "急ぎ")) {
            priority = 5;
            spot.put("priority", priority);
            r.actions.add("最優先入力を検出");
        }

        int rating = clamp(spot.optInt("rating", 3), 1, 5);
        if (AdaptiveRulebook.containsAny(text, "絶景", "夕焼け", "朝日", "滝", "霧", "パノラマ", "映える", "すごい景色")) {
            int next = Math.max(rating, 4);
            if (next != rating) {
                rating = next;
                spot.put("rating", rating);
                r.actions.add("映像価値を入力内容から上方補正");
            }
        }

        int novelty = clamp(spot.optInt("novelty", 3), 1, 5);
        if (AdaptiveRulebook.containsAny(text, "未踏", "初めて", "知られていない", "穴場", "見つけた", "新発見")) {
            int next = Math.max(novelty, 4);
            if (next != novelty) {
                novelty = next;
                spot.put("novelty", novelty);
                r.actions.add("新規性を上方補正");
            }
        }

        String time = AdaptiveRulebook.inferRecommendedTime(text);
        spot.put("recommendedTime", time);
        int opportunity = clamp((priority - 3) * 4 + (rating - 3) * 4 + (novelty - 3) * 3
                + (AdaptiveRulebook.containsAny(text, "撮影", "動画", "youtube", "収録", "shoot") ? 7 : 0), 0, 20);
        int riskPenalty = restricted ? 30 : Math.max(0, (risk - 2) * 6);
        spot.put("adaptiveOpportunity", opportunity);
        spot.put("adaptiveRiskPenalty", riskPenalty);

        int evidence = inferredTags.size() + risks.size();
        if (!"未分類".equals(inferredCategory)) evidence += 2;
        if (!"FLEXIBLE".equals(time)) evidence += 2;
        if (AdaptiveRulebook.containsAny(text, "撮影", "動画", "youtube", "収録", "shoot")) evidence += 2;
        r.confidence = clamp(25 + evidence * 8, 0, 100);

        String spotId = spot.optString("id", "");
        String title = spot.optString("title", "スポット");
        boolean shootIntent = forcePlan || AdaptiveRulebook.containsAny(text, "撮影", "動画", "youtube", "収録", "撮りたい", "shoot");
        boolean strongCandidate = priority >= 4 && rating >= 4 && novelty >= 4 && !spot.optBoolean("filmed", false);
        boolean autopilot = allowGeneration && (forceAuto || r.confidence >= 55);

        if (autopilot && (shootIntent || strongCandidate) && !restricted && !hasGeneratedPlan(root, spotId)) {
            JSONObject plan = generatedPlan(spot, category, time, text);
            root.getJSONArray(PLANS).put(plan);
            r.generatedPlans++;
            r.actions.add("撮影計画を自動生成");
        }

        if (autopilot && (forceScout || risk >= 4 || access <= 2 || restricted)) {
            String missionKey = restricted ? "permission" : risk >= 4 ? "safety" : "scout";
            if (!hasGeneratedMission(root, spotId, missionKey)) {
                JSONObject mission = generatedMission(spot, missionKey, restricted, risk, access);
                root.getJSONArray(MISSIONS).put(mission);
                r.generatedMissions++;
                r.actions.add(restricted ? "立入可否確認ミッションを生成" : "現地下見・安全確認ミッションを生成");
            }
        }

        if (autopilot) {
            List<String> gear = AdaptiveRulebook.recommendedGear(text, category, risk);
            for (String name : gear) {
                if (ensureGear(root, name, spotId)) {
                    r.generatedGear++;
                    r.actions.add("装備追加: " + name);
                }
            }
        }
    }

    private static void adaptLog(JSONObject log, JSONObject root, Result r, boolean allowGeneration, boolean forceAuto) throws Exception {
        String text = textOf(LOGS, log);
        Set<String> tags = new LinkedHashSet<>(AdaptiveRulebook.splitTags(log.optString("tags", "")));
        Set<String> inferred = AdaptiveRulebook.inferTags(text);
        int before = tags.size();
        tags.addAll(inferred);
        if (tags.size() != before) {
            log.put("tags", AdaptiveRulebook.joinTags(tags));
            r.actions.add("探索ログから状況タグを抽出");
        }
        r.signals.addAll(AdaptiveRulebook.riskSignals(text));
        r.confidence = clamp(30 + inferred.size() * 8 + r.signals.size() * 8, 0, 100);

        boolean explicitlyFilmed = AdaptiveRulebook.containsAny(text, "撮影済み", "撮影した", "撮った", "収録した", "収録済み");
        if (explicitlyFilmed && !log.optBoolean("filmed", false)) {
            log.put("filmed", true);
            r.actions.add("記録文から撮影済みを判定");
        }
        if (log.optBoolean("filmed", false)) markLinkedSpotFilmed(root, log.optString("spotId", ""), r);

        boolean revisit = AdaptiveRulebook.containsAny(text, "再訪", "撮り直し", "もう一度", "不足", "次回", "また来る");
        if (allowGeneration && (forceAuto || r.confidence >= 55) && revisit) {
            String sourceId = log.optString("id", "");
            if (!hasGeneratedMission(root, sourceId, "followup")) {
                JSONObject mission = baseGenerated("ログ再訪: " + log.optString("title", "探索ログ"), sourceId, LOGS, "followup");
                mission.put("deadline", "");
                mission.put("priority", 4);
                mission.put("objective", "不足した画・情報・現地条件を再確認して記録を更新する");
                mission.put("progress", 0);
                root.getJSONArray(MISSIONS).put(mission);
                r.generatedMissions++;
                r.actions.add("再訪ミッションを自動生成");
            }
        }
    }

    private static void adaptPlan(JSONObject plan, JSONObject root, Result r, boolean allowGeneration, boolean forceAuto) throws Exception {
        linkSpotByName(plan, root);
        JSONObject spot = findSpot(root, plan.optString("spotId", ""), plan.optString("spot", ""));
        String combined = textOf(PLANS, plan) + " " + (spot == null ? "" : textOf(SPOTS, spot));
        String category = spot == null ? AdaptiveRulebook.inferCategory(combined) : spot.optString("category", AdaptiveRulebook.inferCategory(combined));

        String shots = plan.optString("shots", "").trim();
        if (shots.isEmpty() || "導入 / 歩行 / 引き / ディテール / 締め".equals(shots)) {
            plan.put("shots", AdaptiveRulebook.inferShots(combined, category));
            r.actions.add("スポット内容からショットリストを自動設計");
        }
        String narration = plan.optString("narration", "").trim();
        if (narration.isEmpty() || "ゆっくり解説の要点".equals(narration)) {
            String spotTitle = plan.optString("spot", plan.optString("title", "撮影地"));
            plan.put("narration", spotTitle + "の場所背景 / 現地までの経路 / 見どころ / 現地で気付いた変化 / 撮影時の注意点");
            r.actions.add("ナレーション骨子を自動生成");
        }
        String bgm = plan.optString("bgm", "").trim();
        if (bgm.isEmpty() || "静寂 / 不穏 / 爽快 / ノスタルジー".equals(bgm)) {
            plan.put("bgm", AdaptiveRulebook.inferBgm(combined, category));
            r.actions.add("BGM方向性を自動決定");
        }

        String date = plan.optString("date", "");
        String relative = combined;
        if (AdaptiveRulebook.containsAny(relative, "明後日")) plan.put("date", LocalDate.now().plusDays(2).format(DateTimeFormatter.ISO_LOCAL_DATE));
        else if (AdaptiveRulebook.containsAny(relative, "明日") && date.trim().isEmpty()) plan.put("date", LocalDate.now().plusDays(1).format(DateTimeFormatter.ISO_LOCAL_DATE));
        else if (AdaptiveRulebook.containsAny(relative, "今日") && date.trim().isEmpty()) plan.put("date", LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE));

        int risk = spot == null ? 2 : clamp(spot.optInt("risk", 2), 1, 5);
        r.signals.addAll(AdaptiveRulebook.riskSignals(combined));
        r.confidence = clamp(35 + r.actions.size() * 12 + r.signals.size() * 7, 0, 100);

        if (allowGeneration && (forceAuto || r.confidence >= 50)) {
            String sourceId = plan.optString("id", "");
            List<String> gear = AdaptiveRulebook.recommendedGear(combined, category, risk);
            for (String name : gear) {
                if (ensureGear(root, name, sourceId)) {
                    r.generatedGear++;
                    r.actions.add("計画に必要な装備を追加: " + name);
                }
            }
        }

        if ("DONE".equalsIgnoreCase(plan.optString("status", "")) && spot != null) {
            spot.put("filmed", true);
            spot.put("updatedAt", System.currentTimeMillis());
            r.actions.add("完了した撮影計画からスポットを撮影済みに同期");
        }
    }

    private static void adaptMission(JSONObject mission, Result r) throws Exception {
        String text = textOf(MISSIONS, mission);
        if (AdaptiveRulebook.containsAny(text, "[done]", "#done", "完了済み")) {
            mission.put("progress", 100);
            mission.put("completedAt", System.currentTimeMillis());
            r.actions.add("完了コマンドを検出");
        }
        if (AdaptiveRulebook.containsAny(text, "#urgent", "最優先", "緊急")) {
            mission.put("priority", 5);
            r.actions.add("緊急ミッションへ昇格");
        }
        r.confidence = r.actions.isEmpty() ? 30 : 85;
    }

    private static void adaptAsset(JSONObject asset, JSONObject root, Result r) throws Exception {
        linkSpotByName(asset, root);
        String text = textOf(ASSETS, asset);
        String name = asset.optString("name", "").toLowerCase();
        String type = asset.optString("type", "").trim();
        if (type.isEmpty() || "MEDIA".equalsIgnoreCase(type)) {
            if (endsAny(name, ".jpg", ".jpeg", ".png", ".heic", ".arw")) type = "PHOTO";
            else if (endsAny(name, ".wav", ".mp3", ".aac", ".flac")) type = "AUDIO";
            else if (endsAny(name, ".mp4", ".mov", ".mkv", ".mxf")) type = "VIDEO";
            else if (AdaptiveRulebook.containsAny(text, "ナレーション", "読み上げ", "voice")) type = "NARRATION";
            if (!type.isEmpty()) {
                asset.put("type", type);
                r.actions.add("ファイル名・内容から素材種別を判定");
            }
        }

        String stage = asset.optString("stage", "RAW");
        String inferredStage = stage;
        if (AdaptiveRulebook.containsAny(text, "公開済み", "投稿済み", "published", "アップロード済み")) inferredStage = "PUBLISHED";
        else if (AdaptiveRulebook.containsAny(text, "編集完了", "書き出し済み", "完成", "ready")) inferredStage = "READY";
        else if (AdaptiveRulebook.containsAny(text, "編集中", "編集する", "edit")) inferredStage = "EDIT";
        else if (AdaptiveRulebook.containsAny(text, "採用", "使う", "select", "候補")) inferredStage = "SELECT";
        if (!inferredStage.equals(stage)) {
            asset.put("stage", inferredStage);
            r.actions.add("制作メモからMedia Stageを自動更新: " + inferredStage);
        }
        if ("PUBLISHED".equals(inferredStage)) markLinkedSpotFilmed(root, asset.optString("spotId", ""), r);
        r.confidence = r.actions.isEmpty() ? 30 : clamp(55 + r.actions.size() * 15, 0, 100);
    }

    private static void adaptGear(JSONObject gear, Result r) throws Exception {
        String name = gear.optString("name", "");
        String group = "OTHER";
        if (AdaptiveRulebook.containsAny(name, "カメラ", "レンズ", "nd", "三脚", "ジンバル")) group = "CAMERA";
        else if (AdaptiveRulebook.containsAny(name, "マイク", "録音", "レコーダー")) group = "AUDIO";
        else if (AdaptiveRulebook.containsAny(name, "バッテリー", "充電", "モバイルバッテリー")) group = "POWER";
        else if (AdaptiveRulebook.containsAny(name, "ライト", "ヘッドライト")) group = "LIGHT";
        else if (AdaptiveRulebook.containsAny(name, "雨", "救急", "水", "手袋", "ヘルメット")) group = "SAFETY";
        if (!group.equals(gear.optString("group", ""))) {
            gear.put("group", group);
            r.actions.add("装備カテゴリを自動分類: " + group);
        }
        if (gear.optInt("quantity", 1) < 1) gear.put("quantity", 1);
        r.confidence = "OTHER".equals(group) ? 35 : 75;
    }

    private static JSONObject generatedPlan(JSONObject spot, String category, String time, String text) throws Exception {
        String title = spot.optString("title", "スポット");
        JSONObject p = baseGenerated(title + " 撮影", spot.optString("id", ""), SPOTS, "auto-plan");
        p.put("spot", title);
        p.put("spotId", spot.optString("id", ""));
        p.put("date", "FLEXIBLE");
        p.put("priority", clamp(spot.optInt("priority", 3), 1, 5));
        p.put("shots", AdaptiveRulebook.inferShots(text, category));
        p.put("narration", title + "の背景 / アクセス / 現地の雰囲気 / 見どころ / 注意点 / 撮影後の所感");
        p.put("bgm", AdaptiveRulebook.inferBgm(text, category));
        p.put("recommendedTime", time);
        p.put("status", "PLANNED");
        return p;
    }

    private static JSONObject generatedMission(JSONObject spot, String key, boolean restricted, int risk, int access) throws Exception {
        String title = spot.optString("title", "スポット");
        String missionTitle;
        String objective;
        if (restricted) {
            missionTitle = "立入可否確認: " + title;
            objective = "所有者・管理者・現地表示を確認し、合法かつ安全に立ち入れる根拠を得る。確認できなければ撮影候補から除外する。";
        } else if (risk >= 4) {
            missionTitle = "安全下見: " + title;
            objective = "危険箇所・撤退経路・通信状況・天候条件を確認し、安全に撮影できる条件を記録する。";
        } else {
            missionTitle = "ロケハン: " + title;
            objective = "アクセス経路・光・音・撮影位置を確認し、本撮影に必要な情報を揃える。";
        }
        JSONObject m = baseGenerated(missionTitle, spot.optString("id", ""), SPOTS, key);
        m.put("deadline", "");
        m.put("priority", restricted || risk >= 4 ? 5 : access <= 2 ? 4 : 3);
        m.put("objective", objective);
        m.put("progress", 0);
        m.put("spotId", spot.optString("id", ""));
        return m;
    }

    private static JSONObject baseGenerated(String title, String sourceId, String sourceType, String key) throws Exception {
        long now = System.currentTimeMillis();
        JSONObject o = new JSONObject();
        o.put("id", UUID.randomUUID().toString());
        o.put("title", title);
        o.put("createdAt", now);
        o.put("updatedAt", now);
        o.put("adaptiveGenerated", true);
        o.put("adaptiveSourceId", sourceId);
        o.put("adaptiveSourceType", sourceType);
        o.put("adaptiveKey", key);
        return o;
    }

    private static boolean hasGeneratedPlan(JSONObject root, String sourceId) {
        JSONArray arr = root.optJSONArray(PLANS);
        if (arr == null) return false;
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.optJSONObject(i);
            if (o != null && o.optBoolean("adaptiveGenerated", false)
                    && sourceId.equals(o.optString("adaptiveSourceId"))
                    && "auto-plan".equals(o.optString("adaptiveKey"))) return true;
        }
        return false;
    }

    private static boolean hasGeneratedMission(JSONObject root, String sourceId, String key) {
        JSONArray arr = root.optJSONArray(MISSIONS);
        if (arr == null) return false;
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.optJSONObject(i);
            if (o != null && o.optBoolean("adaptiveGenerated", false)
                    && sourceId.equals(o.optString("adaptiveSourceId"))
                    && key.equals(o.optString("adaptiveKey"))) return true;
        }
        return false;
    }

    private static boolean ensureGear(JSONObject root, String name, String sourceId) throws Exception {
        JSONArray arr = root.getJSONArray(GEAR);
        for (int i = 0; i < arr.length(); i++) {
            JSONObject g = arr.optJSONObject(i);
            if (g != null && name.equalsIgnoreCase(g.optString("name", ""))) return false;
        }
        long now = System.currentTimeMillis();
        JSONObject g = new JSONObject();
        g.put("id", UUID.randomUUID().toString());
        g.put("name", name);
        g.put("quantity", 1);
        g.put("packed", false);
        g.put("adaptiveGenerated", true);
        g.put("adaptiveSourceId", sourceId);
        g.put("adaptiveSourceType", "input");
        g.put("adaptiveKey", "gear:" + name);
        g.put("createdAt", now);
        g.put("updatedAt", now);
        arr.put(g);
        return true;
    }

    private static void linkSpotByName(JSONObject item, JSONObject root) throws Exception {
        if (!item.optString("spotId", "").isEmpty()) return;
        String name = item.optString("spot", "").trim();
        if (name.isEmpty()) return;
        JSONObject spot = findSpot(root, "", name);
        if (spot != null) item.put("spotId", spot.optString("id", ""));
    }

    private static JSONObject findSpot(JSONObject root, String spotId, String title) {
        JSONArray spots = root.optJSONArray(SPOTS);
        if (spots == null) return null;
        for (int i = 0; i < spots.length(); i++) {
            JSONObject s = spots.optJSONObject(i);
            if (s == null) continue;
            if (!spotId.isEmpty() && spotId.equals(s.optString("id", ""))) return s;
            if (!title.isEmpty() && title.equalsIgnoreCase(s.optString("title", ""))) return s;
        }
        return null;
    }

    private static void markLinkedSpotFilmed(JSONObject root, String spotId, Result r) throws Exception {
        if (spotId == null || spotId.isEmpty()) return;
        JSONObject spot = findSpot(root, spotId, "");
        if (spot != null && !spot.optBoolean("filmed", false)) {
            spot.put("filmed", true);
            spot.put("updatedAt", System.currentTimeMillis());
            r.actions.add("関連スポットを撮影済みに同期");
        }
    }

    public static int removeGeneratedChildren(JSONObject root, String sourceId) {
        int removed = 0;
        String[] collections = {PLANS, MISSIONS, GEAR};
        for (String collection : collections) {
            JSONArray arr = root.optJSONArray(collection);
            if (arr == null) continue;
            for (int i = arr.length() - 1; i >= 0; i--) {
                JSONObject o = arr.optJSONObject(i);
                if (o != null && o.optBoolean("adaptiveGenerated", false)
                        && sourceId.equals(o.optString("adaptiveSourceId", ""))) {
                    arr.remove(i);
                    removed++;
                }
            }
        }
        return removed;
    }

    private static String textOf(String type, JSONObject item) {
        StringBuilder sb = new StringBuilder();
        if (SPOTS.equals(type)) append(sb, item, "title", "area", "category", "tags", "note");
        else if (LOGS.equals(type)) append(sb, item, "title", "place", "tags", "memo");
        else if (PLANS.equals(type)) append(sb, item, "title", "spot", "date", "shots", "narration", "bgm");
        else if (MISSIONS.equals(type)) append(sb, item, "title", "deadline", "objective");
        else if (ASSETS.equals(type)) append(sb, item, "name", "type", "spot", "duration", "reference", "note", "stage");
        else if (GEAR.equals(type)) append(sb, item, "name", "group");
        return sb.toString();
    }

    private static void append(StringBuilder sb, JSONObject item, String... keys) {
        for (String key : keys) {
            String v = item.optString(key, "");
            if (!v.isEmpty()) sb.append(' ').append(v);
        }
    }

    private static JSONArray toArray(List<String> values) {
        JSONArray a = new JSONArray();
        for (String v : values) a.put(v);
        return a;
    }

    private static boolean endsAny(String value, String... suffixes) {
        for (String s : suffixes) if (value.endsWith(s)) return true;
        return false;
    }

    private static int clamp(int v, int min, int max) {
        return Math.max(min, Math.min(max, v));
    }
}
