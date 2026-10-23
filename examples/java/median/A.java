import java.util.Arrays;

public class Median {
    /** Return the median of a non-empty array of numbers. */
    public static double median(int[] xs) {
        int[] s = xs.clone();
        Arrays.sort(s);
        int n = s.length;
        if (n % 2 == 1) return s[n / 2];
        return (s[n / 2 - 1] + s[n / 2]) / 2.0;
    }
}
