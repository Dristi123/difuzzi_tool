class ListNode {
    int val;
    ListNode next;
    ListNode(int val) { this.val = val; }
}

class Solution {
    public int sumList(ListNode head) {
        if (head == null) return 0;
        // bug: skips the last node
        int s = 0;
        for (ListNode p = head; p.next != null; p = p.next) s += p.val;
        return s;
    }
}
