package difuzzi.rt;

import java.lang.reflect.*;
import java.util.*;

/**
 * Printing and comparing program values. Objects of A and B come from different class loaders,
 * so user-defined classes (ListNode, TreeNode, ...) are compared by class name and field values.
 */
public final class Values {
    static final double REL_TOL = 1e-9;
    static final int MAX_DEPTH = 50;

    // ---- printing ---------------------------------------------------------------------------------
    public static String repr(Object v) {
        StringBuilder sb = new StringBuilder();
        repr(v, sb, new IdentityHashMap<>(), 0);
        return sb.toString();
    }

    private static void repr(Object v, StringBuilder sb, IdentityHashMap<Object, Boolean> seen, int depth) {
        if (v == null) { sb.append("null"); return; }
        if (sb.length() > 200_000) { sb.append("..."); return; }
        Class<?> c = v.getClass();
        if (v instanceof String) { quote((String) v, sb); return; }
        if (v instanceof Character) { sb.append('\'').append(v).append('\''); return; }
        if (v instanceof Number || v instanceof Boolean) { sb.append(v); return; }
        if (c.isArray()) {
            sb.append('[');
            for (int i = 0, n = Array.getLength(v); i < n; i++) {
                if (i > 0) sb.append(", ");
                repr(Array.get(v, i), sb, seen, depth + 1);
            }
            sb.append(']');
            return;
        }
        if (depth > MAX_DEPTH || seen.containsKey(v)) { sb.append("<cycle>"); return; }
        seen.put(v, true);
        try {
            if (v instanceof Map) {
                sb.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                    if (!first) sb.append(", ");
                    first = false;
                    repr(e.getKey(), sb, seen, depth + 1);
                    sb.append(": ");
                    repr(e.getValue(), sb, seen, depth + 1);
                }
                sb.append('}');
            } else if (v instanceof Collection) {
                sb.append('[');
                boolean first = true;
                for (Object x : (Collection<?>) v) {
                    if (!first) sb.append(", ");
                    first = false;
                    repr(x, sb, seen, depth + 1);
                }
                sb.append(']');
            } else if (isJdk(c) || overrides(c, "toString")) {
                sb.append(v);
            } else {
                sb.append(c.getSimpleName()).append('{');
                boolean first = true;
                for (Field f : fields(c)) {
                    if (!first) sb.append(", ");
                    first = false;
                    sb.append(f.getName()).append('=');
                    repr(get(f, v), sb, seen, depth + 1);
                }
                sb.append('}');
            }
        } finally {
            seen.remove(v);
        }
    }

    public static void quote(String s, StringBuilder sb) {
        sb.append('"');
        for (char ch : s.toCharArray()) {
            switch (ch) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (ch < 0x20 || Character.isSurrogate(ch)) sb.append(String.format("\\u%04x", (int) ch));
                    else sb.append(ch);
            }
        }
        sb.append('"');
    }

    // ---- comparing --------------------------------------------------------------------------------
    public static boolean same(Object a, Object b) {
        try {
            return same(a, b, new IdentityHashMap<>(), 0);
        } catch (RuntimeException | StackOverflowError e) {
            return repr(a).equals(repr(b));
        }
    }

    private static boolean same(Object a, Object b, IdentityHashMap<Object, Object> seen, int depth) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        if (a instanceof Number && b instanceof Number) return sameNumber((Number) a, (Number) b);
        Class<?> ca = a.getClass(), cb = b.getClass();
        if (ca.isArray() || cb.isArray()) {
            if (!(ca.isArray() && cb.isArray())) return false;
            int n = Array.getLength(a);
            if (n != Array.getLength(b)) return false;
            for (int i = 0; i < n; i++) if (!same(Array.get(a, i), Array.get(b, i), seen, depth + 1)) return false;
            return true;
        }
        if (depth > MAX_DEPTH) return a.equals(b);
        if (seen.get(a) == b) return true;   // already being compared (cyclic structure)
        seen.put(a, b);
        if (a instanceof List && b instanceof List) {
            List<?> la = (List<?>) a, lb = (List<?>) b;
            if (la.size() != lb.size()) return false;
            Iterator<?> ia = la.iterator(), ib = lb.iterator();
            while (ia.hasNext()) if (!same(ia.next(), ib.next(), seen, depth + 1)) return false;
            return true;
        }
        if ((a instanceof Set && b instanceof Set) || (a instanceof Map && b instanceof Map)) {
            if (isJdkDeep(a) && isJdkDeep(b)) return a.equals(b);
            return sortedRepr(a).equals(sortedRepr(b));
        }
        if (a instanceof Collection && b instanceof Collection) {
            return same(new ArrayList<>((Collection<?>) a), new ArrayList<>((Collection<?>) b), seen, depth + 1);
        }
        if (isJdk(ca) || isJdk(cb)) return a.equals(b);
        // user-defined classes: possibly the "same" class from two different class loaders
        if (!ca.getName().equals(cb.getName())) return false;
        if (ca == cb && overrides(ca, "equals")) return a.equals(b);
        List<Field> fa = fields(ca), fb = fields(cb);
        if (fa.size() != fb.size()) return false;
        for (int i = 0; i < fa.size(); i++) {
            if (!fa.get(i).getName().equals(fb.get(i).getName())) return false;
            if (!same(get(fa.get(i), a), get(fb.get(i), b), seen, depth + 1)) return false;
        }
        return true;
    }

    static boolean sameNumber(Number a, Number b) {
        boolean fa = a instanceof Double || a instanceof Float, fb = b instanceof Double || b instanceof Float;
        if (!fa && !fb) {
            if (a instanceof java.math.BigInteger || b instanceof java.math.BigInteger
                    || a instanceof java.math.BigDecimal || b instanceof java.math.BigDecimal)
                return new java.math.BigDecimal(a.toString()).compareTo(new java.math.BigDecimal(b.toString())) == 0;
            return a.longValue() == b.longValue();
        }
        double x = a.doubleValue(), y = b.doubleValue();
        if (Double.isNaN(x) || Double.isNaN(y)) return Double.isNaN(x) && Double.isNaN(y);
        if (Double.isInfinite(x) || Double.isInfinite(y)) return x == y;
        return Math.abs(x - y) <= REL_TOL * Math.max(Math.max(Math.abs(x), Math.abs(y)), 1.0);
    }

    private static String sortedRepr(Object v) {
        List<String> parts = new ArrayList<>();
        if (v instanceof Map) for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) parts.add(repr(e.getKey()) + ":" + repr(e.getValue()));
        else for (Object x : (Collection<?>) v) parts.add(repr(x));
        Collections.sort(parts);
        return parts.toString();
    }

    private static boolean isJdkDeep(Object v) {
        Collection<?> items = v instanceof Map ? ((Map<?, ?>) v).keySet() : (Collection<?>) v;
        for (Object x : items) if (x != null && !isJdk(x.getClass())) return false;
        if (v instanceof Map) for (Object x : ((Map<?, ?>) v).values()) if (x != null && !isJdk(x.getClass())) return false;
        return true;
    }

    // ---- reflection helpers -----------------------------------------------------------------------
    static boolean isJdk(Class<?> c) {
        String n = c.getName();
        return c.isPrimitive() || n.startsWith("java.") || n.startsWith("javax.") || n.startsWith("jdk.") || n.startsWith("sun.");
    }

    static boolean overrides(Class<?> c, String name) {
        try {
            Method m = name.equals("equals") ? c.getMethod("equals", Object.class) : c.getMethod(name);
            return m.getDeclaringClass() != Object.class;
        } catch (NoSuchMethodException e) {
            return false;
        }
    }

    static List<Field> fields(Class<?> c) {
        List<Field> out = new ArrayList<>();
        for (Class<?> k = c; k != null && k != Object.class; k = k.getSuperclass()) {
            for (Field f : k.getDeclaredFields()) {
                if (Modifier.isStatic(f.getModifiers()) || f.isSynthetic()) continue;
                out.add(f);
            }
        }
        out.sort(Comparator.comparing(Field::getName));
        return out;
    }

    static Object get(Field f, Object o) {
        try {
            f.setAccessible(true);
            return f.get(o);
        } catch (Exception e) {
            return "<inaccessible>";
        }
    }
}
