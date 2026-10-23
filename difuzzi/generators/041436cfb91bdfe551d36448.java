import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.*;

public class DiffGen {
    public static Object[] generate(FuzzedDataProvider data) {
        // Non-empty array: length 1 to 20
        int n = data.consumeInt(1, 20);
        int[] xs = new int[n];
        for (int i = 0; i < n; i++) {
            xs[i] = data.consumeInt(-1000, 1000);
        }
        return new Object[]{xs};
    }
}
