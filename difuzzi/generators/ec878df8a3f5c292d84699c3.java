import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.*;

public class DiffGen {
    public static String generate(FuzzedDataProvider data) {
        int n = data.consumeInt(0, 20);
        StringBuilder sb = new StringBuilder();
        sb.append(n).append("\n");
        for (int i = 0; i < n; i++) {
            if (i > 0) {
                sb.append(" ");
            }
            sb.append(data.consumeInt(-1000, 1000));
        }
        if (n > 0) {
            sb.append("\n");
        }
        return sb.toString();
    }
}
