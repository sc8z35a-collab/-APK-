package com.rstlab.trailnote.workspace;

import org.json.JSONArray;
import org.json.JSONObject;

/** Offline scoring helpers for exploration and filming decisions. */
public final class PriorityEngine {
    private PriorityEngine() {}

    public static int scoreSpot(JSONObject spot, JSONArray plans, JSONArray assets) {
        int priority = clamp(spot.optInt("priority", 3), 1, 5);
        int rating = clamp(spot.optInt("rating", 3), 1, 5);
        int novelty = clamp(spot.optInt("novelty", 3), 1, 5);
        int access = clamp(spot.optInt("access", 3), 1, 5);
        int risk = clamp(spot.optInt("risk", 2), 1, 5);
        boolean filmed = spot.optBoolean("filmed", false);
        String id = spot.optString("id", "");
        String title = spot.optString("title", "");

        int score = priority * 18 + rating * 9 + novelty * 8 + access * 5 - risk * 8;
        score += clamp(spot.optInt("adaptiveOpportunity", 0), 0, 20);
        score -= clamp(spot.optInt("adaptiveRiskPenalty", 0), 0, 30);

        if (filmed) score -= 55;
        if (hasActivePlan(id, title, plans)) score += 12;
        int media = linkedAssetCount(id, title, assets);
        if (media == 0) score += 8;
        else if (media >= 3) score -= 6;
        if (spot.optBoolean("favorite", false)) score += 8;

        // A restriction signal is not merely another small penalty. TrailNote should
        // not surface a potentially prohibited location as a top filming target.
        if (spot.optBoolean("restrictedAccess", false)) score = Math.min(score, 10);
        return clamp(score, 0, 100);
    }

    public static double distanceKm(double lat1, double lon1, double lat2, double lon2) {
        double r = 6371.0088;
        double p1 = Math.toRadians(lat1);
        double p2 = Math.toRadians(lat2);
        double dp = Math.toRadians(lat2 - lat1);
        double dl = Math.toRadians(lon2 - lon1);
        double a = Math.sin(dp / 2) * Math.sin(dp / 2)
                + Math.cos(p1) * Math.cos(p2) * Math.sin(dl / 2) * Math.sin(dl / 2);
        return r * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    }

    private static boolean hasActivePlan(String spotId, String title, JSONArray plans) {
        for (int i = 0; i < plans.length(); i++) {
            JSONObject p = plans.optJSONObject(i);
            if (p == null || "DONE".equalsIgnoreCase(p.optString("status"))) continue;
            if (!spotId.isEmpty() && spotId.equals(p.optString("spotId"))) return true;
            if (!title.isEmpty() && title.equalsIgnoreCase(p.optString("spot"))) return true;
        }
        return false;
    }

    private static int linkedAssetCount(String spotId, String title, JSONArray assets) {
        int n = 0;
        for (int i = 0; i < assets.length(); i++) {
            JSONObject a = assets.optJSONObject(i);
            if (a == null) continue;
            if (!spotId.isEmpty() && spotId.equals(a.optString("spotId"))) n++;
            else if (!title.isEmpty() && title.equalsIgnoreCase(a.optString("spot"))) n++;
        }
        return n;
    }

    private static int clamp(int v, int min, int max) {
        return Math.max(min, Math.min(max, v));
    }
}
