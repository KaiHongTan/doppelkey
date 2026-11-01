package dev.doppelkey;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Just enough JSON for protocol messages (no dependencies). */
final class Json {
    private Json() {}

    static final class Obj {
        final Map<String, Object> map = new LinkedHashMap<>();

        Obj put(String k, Object v) {
            map.put(k, v);
            return this;
        }

        Obj putAll(Obj o) {
            map.putAll(o.map);
            return this;
        }

        Object get(String k) { return map.get(k); }
        String str(String k) { Object v = map.get(k); return v == null ? null : v.toString(); }
        Obj obj(String k) { Object v = map.get(k); return v instanceof Obj ? (Obj) v : null; }
        boolean has(String k) { return map.containsKey(k); }
    }

    static String write(Object v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object v) {
        if (v == null) sb.append("null");
        else if (v instanceof String) str(sb, (String) v);
        else if (v instanceof Number || v instanceof Boolean) sb.append(v);
        else if (v instanceof Obj) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : ((Obj) v).map.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                str(sb, e.getKey());
                sb.append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
        } else throw new IllegalArgumentException("cannot encode " + v.getClass());
    }

    private static void str(StringBuilder sb, String s) {
        sb.append('"');
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') sb.append('\\').append(c);
            else if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
            else sb.append(c);
        }
        sb.append('"');
    }

    static Object parse(String s) {
        int[] i = {0};
        Object v = value(s, i);
        return v;
    }

    private static void ws(String s, int[] i) {
        while (i[0] < s.length() && Character.isWhitespace(s.charAt(i[0]))) i[0]++;
    }

    private static Object value(String s, int[] i) {
        ws(s, i);
        char c = s.charAt(i[0]);
        if (c == '{') {
            Obj o = new Obj();
            i[0]++;
            ws(s, i);
            if (s.charAt(i[0]) == '}') { i[0]++; return o; }
            while (true) {
                ws(s, i);
                String k = (String) value(s, i);
                ws(s, i);
                i[0]++; // ':'
                o.put(k, value(s, i));
                ws(s, i);
                if (s.charAt(i[0]++) == '}') return o;
            }
        }
        if (c == '[') {
            List<Object> a = new ArrayList<>();
            i[0]++;
            ws(s, i);
            if (s.charAt(i[0]) == ']') { i[0]++; return a; }
            while (true) {
                a.add(value(s, i));
                ws(s, i);
                if (s.charAt(i[0]++) == ']') return a;
            }
        }
        if (c == '"') {
            StringBuilder sb = new StringBuilder();
            i[0]++;
            while (true) {
                char ch = s.charAt(i[0]++);
                if (ch == '"') return sb.toString();
                if (ch == '\\') {
                    char e = s.charAt(i[0]++);
                    switch (e) {
                        case 'n': sb.append('\n'); break;
                        case 't': sb.append('\t'); break;
                        case 'r': sb.append('\r'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'u': sb.append((char) Integer.parseInt(s.substring(i[0], i[0] + 4), 16)); i[0] += 4; break;
                        default: sb.append(e);
                    }
                } else sb.append(ch);
            }
        }
        if (s.startsWith("true", i[0])) { i[0] += 4; return Boolean.TRUE; }
        if (s.startsWith("false", i[0])) { i[0] += 5; return Boolean.FALSE; }
        if (s.startsWith("null", i[0])) { i[0] += 4; return null; }
        int start = i[0];
        while (i[0] < s.length() && "+-0123456789.eE".indexOf(s.charAt(i[0])) >= 0) i[0]++;
        String num = s.substring(start, i[0]);
        return num.contains(".") || num.contains("e") || num.contains("E") ? (Object) Double.parseDouble(num) : (Object) Long.parseLong(num);
    }
}
