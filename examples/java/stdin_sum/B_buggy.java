import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        int n = sc.nextInt();
        if (n == 0) System.exit(1);               // bug: rejects an empty list
        long total = 0;
        int max = Integer.MIN_VALUE;
        for (int i = 0; i < n; i++) {
            int x = sc.nextInt();
            max = Math.max(max, x);
            if (x > 0) total += x;
        }
        // bug: prints the largest number when every number is negative
        System.out.println(max < 0 ? max : total);
    }
}
