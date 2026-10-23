def search(xs, t):
    lo, hi = 0, len(xs)
    while lo < hi:
        mid = (lo + hi) // 2
        if xs[mid] <= t:        # returns the position after t, not t's index
            lo = mid + 1
        else:
            hi = mid
    return lo if lo < len(xs) and lo > 0 and xs[lo - 1] == t else -1
