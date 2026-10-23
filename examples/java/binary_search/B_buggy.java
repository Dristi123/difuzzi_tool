class Solution {
    public int search(int[] xs, int t) {
        int lo = 0, hi = xs.length - 1;
        while (lo < hi) {                       // off by one: misses t when it is the last element left
            int mid = (lo + hi) / 2;
            if (xs[mid] == t) return mid;
            if (xs[mid] < t) lo = mid + 1;
            else hi = mid - 1;
        }
        return -1;
    }
}
