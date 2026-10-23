import java.util.Arrays;

public class Median {
    public static double median(int[] xs) {
        int[] s = xs.clone();
        Arrays.sort(s);
        // bug: for even lengths, takes the upper middle element instead of the average
        return s[s.length / 2];
    }
}
