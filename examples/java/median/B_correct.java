import java.util.stream.IntStream;

public class Median {
    public static double median(int[] values) {
        int[] s = IntStream.of(values).sorted().toArray();
        int mid = s.length / 2;
        return s.length % 2 == 1 ? s[mid] : (s[mid - 1] + (double) s[mid]) / 2;
    }
}
