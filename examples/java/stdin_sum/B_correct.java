import java.io.*;
import java.util.*;

public class Main {
    public static void main(String[] args) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        int n = Integer.parseInt(br.readLine().trim());
        long total = 0;
        StringTokenizer st = new StringTokenizer(n > 0 ? br.readLine() : "");
        for (int i = 0; i < n; i++) total += Math.max(0, Integer.parseInt(st.nextToken()));
        System.out.println(total);
    }
}
