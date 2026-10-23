def median(xs):
    s = sorted(xs)
    # bug: for even lengths, takes the upper middle element instead of the average
    return s[len(s) // 2]
