import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.*;

public class DiffGen {
    public static Object[] generate(FuzzedDataProvider data) {
        int n = data.consumeInt(0, 20);
        ListNode head = null;
        for (int i = 0; i < n; i++) {
            ListNode node = new ListNode(data.consumeInt(-1000, 1000));
            node.next = head;
            head = node;
        }
        return new Object[]{head};
    }
}
