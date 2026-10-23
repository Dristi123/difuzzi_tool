package difuzzi.rt;

import java.util.*;

/** Minimal JSON writer for the result file (maps, lists, strings, numbers, booleans, null). */
public final class Json {
    public static String write(Object v) {
        StringBuilder sb = new StringBuilder();
        write(v, sb, 0);
        return sb.toString();
    }

    private static void write(Object v, StringBuilder sb, int indent) {
        if (v == null) sb.append("null");
        else if (v instanceof String) Values.quote((String) v, sb);
        else if (v instanceof Double && (((Double) v).isNaN() || ((Double) v).isInfinite())) sb.append("null");
        else if (v instanceof Number || v instanceof Boolean) sb.append(v);
        else if (v instanceof Map) {
            sb.append("{");
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                sb.append(first ? "\n" : ",\n").append(" ".repeat(indent + 1));
                first = false;
                Values.quote(String.valueOf(e.getKey()), sb);
                sb.append(": ");
                write(e.getValue(), sb, indent + 1);
            }
            sb.append(first ? "}" : "\n" + " ".repeat(indent) + "}");
        } else if (v instanceof Collection) {
            sb.append("[");
            boolean first = true;
            for (Object x : (Collection<?>) v) {
                if (!first) sb.append(", ");
                first = false;
                write(x, sb, indent + 1);
            }
            sb.append("]");
        } else Values.quote(String.valueOf(v), sb);
    }
}
