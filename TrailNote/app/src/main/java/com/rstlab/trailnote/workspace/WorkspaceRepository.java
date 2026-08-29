package com.rstlab.trailnote.workspace;

import android.content.Context;
import android.content.SharedPreferences;

import com.rstlab.trailnote.SecurityVault;
import com.rstlab.trailnote.workspace.adaptive.AdaptiveOperationsCore;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Encrypted TrailNote operations workspace.
 *
 * Every mutation is persisted through SecurityVault and passed through Adaptive
 * Operations Core so user-entered content can trigger deterministic offline
 * classification, linking, safety responses and production follow-up actions.
 */
public final class WorkspaceRepository {
    public static final String LOGS = "logs";
    public static final String SPOTS = "spots";
    public static final String PLANS = "plans";
    public static final String MISSIONS = "missions";
    public static final String ASSETS = "assets";
    public static final String GEAR = "gear";

    private static final int SCHEMA = 3;
    private static final String PREFS = "trailnote_prefs";
    private static final String LEGACY_KEY = "entries";

    public static final class SearchHit {
        public final String type;
        public final String id;
        public final String title;
        public final String subtitle;

        SearchHit(String type, String id, String title, String subtitle) {
            this.type = type;
            this.id = id;
            this.title = title;
            this.subtitle = subtitle;
        }
    }

    public static final class Candidate {
        public final JSONObject spot;
        public final int score;
        Candidate(JSONObject spot, int score) {
            this.spot = spot;
            this.score = score;
        }
    }

    private final SecurityVault vault;
    private final SharedPreferences legacyPrefs;
    private JSONObject root;
    private AdaptiveOperationsCore.Result lastAdaptiveResult;

    public WorkspaceRepository(Context context, SecurityVault vault) {
        this.vault = vault;
        this.legacyPrefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public synchronized void load() throws Exception {
        String raw = vault.loadEntries(legacyPrefs, LEGACY_KEY);
        boolean migrated = false;
        if (raw == null || raw.trim().isEmpty()) {
            root = newRoot();
            migrated = true;
        } else {
            String t = raw.trim();
            if (t.startsWith("[")) {
                root = newRoot();
                root.put(LOGS, normalizeLegacyLogs(new JSONArray(t)));
                migrated = true;
            } else {
                root = new JSONObject(t);
            }
        }
        migrated |= normalizeRoot();
        migrated |= AdaptiveOperationsCore.upgradeWorkspace(root);
        if (migrated) save();
    }

    public synchronized String toJson() throws Exception {
        requireLoaded();
        return root.toString();
    }

    public synchronized void replaceJson(String json) throws Exception {
        if (json == null) throw new IllegalArgumentException("バックアップが空です");
        String t = json.trim();
        if (t.startsWith("[")) {
            root = newRoot();
            root.put(LOGS, normalizeLegacyLogs(new JSONArray(t)));
        } else {
            root = new JSONObject(t);
        }
        normalizeRoot();
        AdaptiveOperationsCore.upgradeWorkspace(root);
        save();
    }

    public synchronized JSONArray array(String type) throws Exception {
        requireLoaded();
        return root.getJSONArray(type);
    }

    public synchronized int count(String type) throws Exception {
        return array(type).length();
    }

    public synchronized int totalObjects() throws Exception {
        return count(LOGS) + count(SPOTS) + count(PLANS) + count(MISSIONS) + count(ASSETS) + count(GEAR);
    }

    public synchronized AdaptiveOperationsCore.Result lastAdaptiveResult() {
        return lastAdaptiveResult;
    }

    public synchronized JSONObject add(String type, JSONObject item) throws Exception {
        requireType(type);
        requireLoaded();
        long now = System.currentTimeMillis();
        if (item.optString("id", "").isEmpty()) item.put("id", UUID.randomUUID().toString());
        if (!item.has("createdAt")) item.put("createdAt", now);
        item.put("updatedAt", now);
        root.getJSONArray(type).put(item);
        runAdaptive(type, item, true);
        save();
        return item;
    }

    public synchronized boolean delete(String type, String id) throws Exception {
        JSONArray arr = array(type);
        for (int i = 0; i < arr.length(); i++) {
            if (id.equals(arr.getJSONObject(i).optString("id"))) {
                arr.remove(i);
                int removed = AdaptiveOperationsCore.removeGeneratedChildren(root, id);
                root.put("lastAdaptiveAt", System.currentTimeMillis());
                root.put("lastAdaptiveType", "delete:" + type);
                root.put("lastAdaptiveGenerated", -removed);
                save();
                return true;
            }
        }
        return false;
    }

    public synchronized JSONObject find(String type, String id) throws Exception {
        JSONArray arr = array(type);
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.getJSONObject(i);
            if (id.equals(o.optString("id"))) return o;
        }
        return null;
    }

    public synchronized boolean setBoolean(String type, String id, String key, boolean value) throws Exception {
        JSONObject o = find(type, id);
        if (o == null) return false;
        o.put(key, value);
        o.put("updatedAt", System.currentTimeMillis());
        runAdaptive(type, o, true);
        save();
        return true;
    }

    public synchronized boolean setInt(String type, String id, String key, int value) throws Exception {
        JSONObject o = find(type, id);
        if (o == null) return false;
        o.put(key, value);
        o.put("updatedAt", System.currentTimeMillis());
        runAdaptive(type, o, true);
        save();
        return true;
    }

    public synchronized boolean setString(String type, String id, String key, String value) throws Exception {
        JSONObject o = find(type, id);
        if (o == null) return false;
        o.put(key, value == null ? "" : value);
        o.put("updatedAt", System.currentTimeMillis());
        runAdaptive(type, o, true);
        save();
        return true;
    }

    public synchronized List<SearchHit> search(String query) throws Exception {
        String q = query == null ? "" : query.trim().toLowerCase(Locale.ROOT);
        List<SearchHit> hits = new ArrayList<>();
        if (q.isEmpty()) return hits;
        collectHits(hits, LOGS, q, "探索ログ");
        collectHits(hits, SPOTS, q, "スポット");
        collectHits(hits, PLANS, q, "撮影計画");
        collectHits(hits, MISSIONS, q, "ミッション");
        collectHits(hits, ASSETS, q, "素材");
        collectHits(hits, GEAR, q, "装備");
        if (hits.size() > 50) return new ArrayList<>(hits.subList(0, 50));
        return hits;
    }

    public synchronized List<JSONObject> recent(String type, int limit) throws Exception {
        JSONArray arr = array(type);
        List<JSONObject> list = new ArrayList<>();
        for (int i = 0; i < arr.length(); i++) list.add(arr.getJSONObject(i));
        list.sort((a, b) -> Long.compare(b.optLong("updatedAt", b.optLong("createdAt", 0)), a.optLong("updatedAt", a.optLong("createdAt", 0))));
        if (list.size() > limit) return new ArrayList<>(list.subList(0, limit));
        return list;
    }

    public synchronized List<Candidate> rankedCandidates() throws Exception {
        JSONArray spots = array(SPOTS);
        JSONArray plans = array(PLANS);
        JSONArray assets = array(ASSETS);
        List<Candidate> out = new ArrayList<>();
        for (int i = 0; i < spots.length(); i++) {
            JSONObject spot = spots.getJSONObject(i);
            out.add(new Candidate(spot, PriorityEngine.scoreSpot(spot, plans, assets)));
        }
        out.sort((a, b) -> Integer.compare(b.score, a.score));
        return out;
    }

    public synchronized Map<String, Integer> categoryCounts() throws Exception {
        Map<String, Integer> map = new LinkedHashMap<>();
        JSONArray spots = array(SPOTS);
        for (int i = 0; i < spots.length(); i++) {
            String category = spots.getJSONObject(i).optString("category", "未分類").trim();
            if (category.isEmpty()) category = "未分類";
            map.put(category, map.containsKey(category) ? map.get(category) + 1 : 1);
        }
        return map;
    }

    public synchronized int countTrue(String type, String key) throws Exception {
        JSONArray arr = array(type);
        int n = 0;
        for (int i = 0; i < arr.length(); i++) if (arr.getJSONObject(i).optBoolean(key, false)) n++;
        return n;
    }

    public synchronized int countStatus(String type, String key, String expected) throws Exception {
        JSONArray arr = array(type);
        int n = 0;
        for (int i = 0; i < arr.length(); i++) {
            if (expected.equalsIgnoreCase(arr.getJSONObject(i).optString(key, ""))) n++;
        }
        return n;
    }

    public synchronized int missionAverageProgress() throws Exception {
        JSONArray arr = array(MISSIONS);
        if (arr.length() == 0) return 0;
        int total = 0;
        for (int i = 0; i < arr.length(); i++) total += clamp(arr.getJSONObject(i).optInt("progress", 0), 0, 100);
        return total / arr.length();
    }

    public synchronized int planCompletionPercent() throws Exception {
        int total = count(PLANS);
        if (total == 0) return 0;
        return countStatus(PLANS, "status", "DONE") * 100 / total;
    }

    public synchronized int mediaPublishedPercent() throws Exception {
        int total = count(ASSETS);
        if (total == 0) return 0;
        return countStatus(ASSETS, "stage", "PUBLISHED") * 100 / total;
    }

    public synchronized int gearReadyPercent() throws Exception {
        int total = count(GEAR);
        if (total == 0) return 0;
        return countTrue(GEAR, "packed") * 100 / total;
    }

    public synchronized void seedStarterGearIfEmpty() throws Exception {
        if (count(GEAR) != 0) return;
        String[] names = {"メインカメラ", "予備バッテリー", "SDカード", "マイク", "雨対策", "飲料水"};
        for (String name : names) {
            JSONObject o = new JSONObject();
            o.put("id", UUID.randomUUID().toString());
            o.put("name", name);
            o.put("quantity", 1);
            o.put("packed", false);
            o.put("createdAt", System.currentTimeMillis());
            o.put("updatedAt", System.currentTimeMillis());
            root.getJSONArray(GEAR).put(o);
            AdaptiveOperationsCore.apply(GEAR, o, root, false);
        }
        save();
    }

    public synchronized JSONObject summaryJson() throws Exception {
        JSONObject s = new JSONObject();
        s.put("schema", SCHEMA);
        s.put("adaptiveEngine", root.optString("adaptiveEngineVersion", AdaptiveOperationsCore.ENGINE_VERSION));
        s.put("lastAdaptiveAt", root.optLong("lastAdaptiveAt", 0));
        s.put("lastAdaptiveGenerated", root.optInt("lastAdaptiveGenerated", 0));
        s.put("logs", count(LOGS));
        s.put("spots", count(SPOTS));
        s.put("plans", count(PLANS));
        s.put("missions", count(MISSIONS));
        s.put("assets", count(ASSETS));
        s.put("gear", count(GEAR));
        s.put("planCompletion", planCompletionPercent());
        s.put("missionProgress", missionAverageProgress());
        s.put("mediaPublished", mediaPublishedPercent());
        s.put("gearReady", gearReadyPercent());
        return s;
    }

    private void runAdaptive(String type, JSONObject item, boolean allowGeneration) throws Exception {
        lastAdaptiveResult = AdaptiveOperationsCore.apply(type, item, root, allowGeneration);
        root.put("adaptiveEngineVersion", AdaptiveOperationsCore.ENGINE_VERSION);
        root.put("lastAdaptiveAt", System.currentTimeMillis());
        root.put("lastAdaptiveType", type);
        root.put("lastAdaptiveSourceId", item.optString("id", ""));
        root.put("lastAdaptiveConfidence", lastAdaptiveResult.confidence);
        root.put("lastAdaptiveGenerated", lastAdaptiveResult.generatedTotal());
        JSONArray actions = new JSONArray();
        for (String action : lastAdaptiveResult.actions) actions.put(action);
        root.put("lastAdaptiveActions", actions);
    }

    private void collectHits(List<SearchHit> hits, String type, String q, String typeLabel) throws Exception {
        JSONArray arr = array(type);
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.getJSONObject(i);
            String text = o.toString().toLowerCase(Locale.ROOT);
            if (!text.contains(q)) continue;
            String title = titleOf(type, o);
            String subtitle = subtitleOf(type, o);
            hits.add(new SearchHit(typeLabel, o.optString("id"), title, subtitle));
        }
    }

    private static String titleOf(String type, JSONObject o) {
        if (GEAR.equals(type)) return o.optString("name", "装備");
        if (ASSETS.equals(type)) return o.optString("name", "素材");
        return o.optString("title", "無題");
    }

    private static String subtitleOf(String type, JSONObject o) {
        if (LOGS.equals(type)) return o.optString("place", "");
        if (SPOTS.equals(type)) return o.optString("area", "") + " / " + o.optString("category", "未分類");
        if (PLANS.equals(type)) return o.optString("date", "") + " / " + o.optString("status", "PLANNED");
        if (MISSIONS.equals(type)) return o.optInt("progress", 0) + "% / " + o.optString("deadline", "期限なし");
        if (ASSETS.equals(type)) return o.optString("type", "MEDIA") + " / " + o.optString("stage", "RAW");
        if (GEAR.equals(type)) return o.optBoolean("packed", false) ? "準備済み" : "未準備";
        return "";
    }

    private boolean normalizeRoot() throws Exception {
        boolean changed = false;
        if (root.optInt("schema", 0) != SCHEMA) {
            root.put("schema", SCHEMA);
            changed = true;
        }
        String[] arrays = {LOGS, SPOTS, PLANS, MISSIONS, ASSETS, GEAR};
        for (String key : arrays) {
            if (!(root.opt(key) instanceof JSONArray)) {
                root.put(key, new JSONArray());
                changed = true;
            }
        }
        if (!root.has("createdAt")) {
            root.put("createdAt", System.currentTimeMillis());
            changed = true;
        }
        return changed;
    }

    private JSONArray normalizeLegacyLogs(JSONArray in) throws Exception {
        JSONArray out = new JSONArray();
        for (int i = 0; i < in.length(); i++) {
            JSONObject o = in.getJSONObject(i);
            if (o.optString("id", "").isEmpty()) o.put("id", UUID.randomUUID().toString());
            long created = o.optLong("createdAt", System.currentTimeMillis());
            o.put("createdAt", created);
            if (!o.has("updatedAt")) o.put("updatedAt", created);
            out.put(o);
        }
        return out;
    }

    private JSONObject newRoot() throws Exception {
        JSONObject r = new JSONObject();
        long now = System.currentTimeMillis();
        r.put("schema", SCHEMA);
        r.put("createdAt", now);
        r.put("updatedAt", now);
        r.put("adaptiveEngineVersion", AdaptiveOperationsCore.ENGINE_VERSION);
        r.put(LOGS, new JSONArray());
        r.put(SPOTS, new JSONArray());
        r.put(PLANS, new JSONArray());
        r.put(MISSIONS, new JSONArray());
        r.put(ASSETS, new JSONArray());
        r.put(GEAR, new JSONArray());
        return r;
    }

    private synchronized void save() throws Exception {
        requireLoaded();
        root.put("schema", SCHEMA);
        root.put("updatedAt", System.currentTimeMillis());
        vault.saveEntries(root.toString());
    }

    private void requireLoaded() {
        if (root == null) throw new IllegalStateException("Workspace is not loaded");
    }

    private static void requireType(String type) {
        if (!LOGS.equals(type) && !SPOTS.equals(type) && !PLANS.equals(type)
                && !MISSIONS.equals(type) && !ASSETS.equals(type) && !GEAR.equals(type)) {
            throw new IllegalArgumentException("Unknown workspace collection: " + type);
        }
    }

    private static int clamp(int v, int min, int max) {
        return Math.max(min, Math.min(max, v));
    }
}
