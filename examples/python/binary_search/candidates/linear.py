def search(xs, t):
    for i, x in enumerate(xs):
        if x == t:
            return i
    return -1
