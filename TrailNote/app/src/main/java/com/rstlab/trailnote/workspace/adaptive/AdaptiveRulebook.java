package com.rstlab.trailnote.workspace.adaptive;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Deterministic offline semantic rulebook used by Adaptive Operations Core. */
public final class AdaptiveRulebook {
    private AdaptiveRulebook() {}

    public static final class CategoryRule {
        public final String category;
        public final int weight;
        public final String[] keywords;

        CategoryRule(String category, int weight, String... keywords) {
            this.category = category;
            this.weight = weight;
            this.keywords = keywords;
        }
    }

    public static final CategoryRule[] CATEGORY_RULES = {
            new CategoryRule("廃道・道路", 6, "旧道", "廃道", "林道", "峠道", "酷道", "隧道", "トンネル", "road", "trail"),
            new CategoryRule("森", 5, "森", "森林", "樹海", "杉林", "竹林", "木漏れ日", "forest", "woodland"),
            new CategoryRule("山", 5, "山", "峰", "峠", "稜線", "登山", "山頂", "尾根", "mountain", "ridge"),
            new CategoryRule("川・渓谷", 5, "川", "沢", "渓谷", "滝", "河原", "清流", "峡谷", "river", "waterfall", "stream"),
            new CategoryRule("集落・農村", 5, "集落", "農村", "田舎", "里山", "棚田", "民家", "村", "village", "rural"),
            new CategoryRule("廃墟", 7, "廃墟", "廃屋", "廃校", "廃工場", " abandoned ", "ruin"),
            new CategoryRule("海岸", 5, "海", "海岸", "岬", "浜", "漁港", "海辺", "coast", "beach", "ocean"),
            new CategoryRule("鉄道", 6, "鉄道", "駅", "線路", "廃線", "踏切", "鉄橋", "railway", "station"),
            new CategoryRule("史跡", 5, "史跡", "城跡", "神社", "寺", "古道", "石碑", "遺構", "historic", "shrine", "temple"),
            new CategoryRule("洞窟", 7, "洞窟", "鍾乳洞", "坑道", "防空壕", "cave", "tunnel interior"),
            new CategoryRule("都市", 4, "都市", "街", "商店街", "高架", "夜景", "city", "urban")
    };

    public static String normalize(String value) {
        if (value == null) return "";
        return value.toLowerCase(Locale.ROOT)
                .replace('　', ' ')
                .replace('，', ',')
                .replace('、', ',');
    }

    public static boolean containsAny(String text, String... words) {
        String n = normalize(text);
        for (String word : words) {
            if (!word.isEmpty() && n.contains(normalize(word))) return true;
        }
        return false;
    }

    public static int keywordHits(String text, String... words) {
        int n = 0;
        String normalized = normalize(text);
        for (String word : words) if (!word.isEmpty() && normalized.contains(normalize(word))) n++;
        return n;
    }

    public static String inferCategory(String text) {
        Map<String, Integer> scores = new LinkedHashMap<>();
        String n = normalize(text);
        for (CategoryRule rule : CATEGORY_RULES) {
            int hits = 0;
            for (String keyword : rule.keywords) if (n.contains(normalize(keyword))) hits++;
            if (hits > 0) scores.put(rule.category, hits * rule.weight);
        }
        String best = "未分類";
        int bestScore = 0;
        for (Map.Entry<String, Integer> e : scores.entrySet()) {
            if (e.getValue() > bestScore) {
                best = e.getKey();
                bestScore = e.getValue();
            }
        }
        return best;
    }

    public static Set<String> inferTags(String text) {
        Set<String> out = new LinkedHashSet<>();
        addTag(out, text, "朝", "朝日", "日の出", "sunrise", "早朝");
        addTag(out, text, "夕景", "夕日", "夕焼け", "sunset", "黄昏");
        addTag(out, text, "夜間", "夜", "夜景", "星", "星空", "night");
        addTag(out, text, "霧", "霧", "靄", "もや", "fog", "mist");
        addTag(out, text, "雨天", "雨", "豪雨", "小雨", "rain");
        addTag(out, text, "雪", "雪", "積雪", "snow");
        addTag(out, text, "自転車", "自転車", "ロードバイク", "クロスバイク", "bike", "cycling");
        addTag(out, text, "徒歩", "徒歩", "歩き", "散策", "walking", "hike");
        addTag(out, text, "環境音", "環境音", "川音", "鳥の声", "静寂", "ambient", "soundscape");
        addTag(out, text, "廃景", "廃墟", "廃道", "廃線", "廃校", "ruin", "abandoned");
        addTag(out, text, "水辺", "川", "滝", "沢", "海", "湖", "水辺", "river", "waterfall");
        addTag(out, text, "パノラマ", "展望", "眺望", "絶景", "パノラマ", "panorama", "viewpoint");
        addTag(out, text, "野生動物", "熊", "クマ", "猪", "イノシシ", "鹿", "猿", "wildlife");
        addTag(out, text, "撮影候補", "撮影", "動画", "youtube", "収録", "film", "shoot");
        return out;
    }

    private static void addTag(Set<String> out, String text, String tag, String... words) {
        if (containsAny(text, words)) out.add(tag);
    }

    public static List<String> riskSignals(String text) {
        List<String> out = new ArrayList<>();
        signal(out, text, "崖・転落", "崖", "断崖", "転落", "急斜面", "崩落", "落石", "cliff");
        signal(out, text, "野生動物", "熊", "クマ", "猪", "イノシシ", "毒蛇", "マムシ", "wild bear");
        signal(out, text, "増水・水難", "増水", "洪水", "急流", "渡渉", "深い川", "flood");
        signal(out, text, "暗所", "洞窟", "坑道", "暗闇", "夜間", "真っ暗", "cave");
        signal(out, text, "路面・足場", "ぬかるみ", "滑落", "倒木", "崩れ", "悪路", "足場が悪い");
        signal(out, text, "通信圏外", "圏外", "電波なし", "no signal", "remote");
        signal(out, text, "立入制限", "立入禁止", "進入禁止", "私有地", "封鎖", "立ち入り禁止", "no trespassing");
        return out;
    }

    private static void signal(List<String> out, String text, String label, String... words) {
        if (containsAny(text, words)) out.add(label);
    }

    public static boolean hasPermissionSignal(String text) {
        return containsAny(text, "許可済", "許可を得", "許可あり", "permission granted", "所有者許可");
    }

    public static String inferRecommendedTime(String text) {
        if (containsAny(text, "朝日", "日の出", "早朝", "sunrise")) return "SUNRISE";
        if (containsAny(text, "夕日", "夕焼け", "黄昏", "sunset")) return "SUNSET";
        if (containsAny(text, "夜景", "星空", "夜", "night")) return "NIGHT";
        if (containsAny(text, "霧", "靄", "fog", "mist")) return "EARLY_MORNING";
        if (containsAny(text, "木漏れ日", "柔らかい光", "golden hour")) return "GOLDEN_HOUR";
        return "FLEXIBLE";
    }

    public static String inferBgm(String text, String category) {
        if (containsAny(text, "不穏", "廃墟", "廃道", "洞窟", "怖", "mysterious")) return "静かな不穏 / 低密度アンビエント";
        if (containsAny(text, "夕日", "夕焼け", "集落", "田舎", "里山", "nostalg")) return "ノスタルジー / 穏やかなピアノ";
        if (containsAny(text, "川", "滝", "森", "清流", "自然音")) return "環境音主体 / 薄いアンビエント";
        if (containsAny(text, "自転車", "峠", "爽快", "cycling")) return "軽快 / 透明感のあるBGM";
        if ("都市".equals(category)) return "ミニマル / 都市アンビエント";
        return "静寂寄り / 映像を邪魔しないアンビエント";
    }

    public static String inferShots(String text, String category) {
        if ("川・渓谷".equals(category)) return "導入ワイド / 水流・滝ワイド / 岩肌ディテール / 足元追従 / 環境音30秒 / 締め";
        if ("廃道・道路".equals(category)) return "入口 / 路面ディテール / POV歩行 / カーブ先の見通し / 周辺ワイド / 戻りの締め";
        if ("集落・農村".equals(category)) return "集落入口 / 道 / 建物ディテール / 生活痕跡 / 風景ワイド / 退出カット";
        if ("森".equals(category)) return "森の入口 / 木漏れ日 / 足元 / 歩行追従 / 樹冠ワイド / 環境音 / 締め";
        if ("山".equals(category)) return "アプローチ / 稜線ワイド / 足元 / パン / 展望 / 風音 / 下山カット";
        if ("廃墟".equals(category)) return "外観 / 接近 / 安全な範囲のディテール / 周辺環境 / 固定長回し / 撤収カット";
        if ("鉄道".equals(category)) return "駅・線路全景 / 標識 / レールディテール / 進行方向 / 周辺風景 / 締め";
        return "導入 / 歩行・移動 / ワイド / ディテール / 環境音 / 締め";
    }

    public static List<String> recommendedGear(String text, String category, int risk) {
        Set<String> gear = new LinkedHashSet<>();
        if (containsAny(text, "夜", "夜景", "洞窟", "暗闇", "night")) {
            gear.add("ヘッドライト");
            gear.add("予備ライト");
        }
        if (containsAny(text, "雨", "川", "滝", "沢", "海", "霧", "snow", "rain")) {
            gear.add("カメラ雨対策");
            gear.add("レンズクロス");
        }
        if (containsAny(text, "自転車", "cycling", "bike")) {
            gear.add("自転車用ライト");
            gear.add("携帯工具");
        }
        if (containsAny(text, "圏外", "長時間", "遠い", "山", "峠", "remote") || risk >= 4) {
            gear.add("モバイルバッテリー");
            gear.add("救急セット");
            gear.add("飲料水");
        }
        if ("山".equals(category) || "森".equals(category) || "廃道・道路".equals(category)) gear.add("予備バッテリー");
        return new ArrayList<>(gear);
    }

    public static Set<String> splitTags(String tags) {
        Set<String> out = new LinkedHashSet<>();
        if (tags == null) return out;
        for (String p : normalize(tags).split("[,#]")) {
            String v = p.trim();
            if (!v.isEmpty()) out.add(v);
        }
        return out;
    }

    public static String joinTags(Set<String> tags) {
        StringBuilder sb = new StringBuilder();
        for (String tag : tags) {
            if (tag == null || tag.trim().isEmpty()) continue;
            if (sb.length() > 0) sb.append(", ");
            sb.append(tag.trim());
        }
        return sb.toString();
    }

    public static List<String> words(String... values) {
        return Arrays.asList(values);
    }
}
