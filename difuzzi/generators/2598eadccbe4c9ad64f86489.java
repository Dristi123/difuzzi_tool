import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.*;

public class DiffGen {
    public static Object[] generate(FuzzedDataProvider data) {
        int n = data.consumeInt(0, 20);
        int[] temp = new int[n];
        for (int i = 0; i < n; i++) {
            temp[i] = data.consumeInt(-1000, 1000);
        }
        Arrays.sort(temp);
        
        // Remove duplicates to satisfy "without duplicates" constraint
        int m = 0;
        for (int i = 0; i < n; i++) {
            if (i == 0 || temp[i] != temp[i - 1]) {
                temp[m++] = temp[i];
            }
        }
        int[] xs = Arrays.copyOf(temp, m);
        
        // Generate target: sometimes present in xs, sometimes arbitrary
        int t;
        if (xs.length > 0 && data.consumeBoolean()) {
            t = xs[data.consumeInt(0, xs.length - 1)];
        } else {
            t = data.consumeInt(-1000, 1000);
        }
        
        return new Object[]{xs, t};
    }
}
