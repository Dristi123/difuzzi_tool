def search(xs, t):
    lo, hi = 0, len(xs) - 1
    while lo < hi:              # off by one: misses t when it is the last element left
        mid = (lo + hi) // 2
        if xs[mid] == t:
            return mid
        if xs[mid] < t:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1
