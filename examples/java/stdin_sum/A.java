import java.util.Scanner;

public class Main {
    static Scanner sc = new Scanner(System.in);   // static reader: needs a fresh state per run
    static long total = 0;

    public static void main(String[] args) {
        int n = sc.nextInt();
        for (int i = 0; i < n; i++) {
            int x = sc.nextInt();
            if (x > 0) total += x;
        }
        System.out.println(total);
    }
}
