from bisect import bisect_left


def search(xs, t):
    i = bisect_left(xs, t)
    return i if i < len(xs) and xs[i] == t else -1
