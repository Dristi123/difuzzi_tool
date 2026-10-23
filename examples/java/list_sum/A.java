class ListNode {
    int val;
    ListNode next;
    ListNode(int val) { this.val = val; }
}

class Solution {
    /** Sum of the values in a singly linked list. */
    public int sumList(ListNode head) {
        int s = 0;
        for (ListNode p = head; p != null; p = p.next) s += p.val;
        return s;
    }
}
