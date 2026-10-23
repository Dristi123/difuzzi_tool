def median(values):
    values = sorted(values)
    mid = len(values) // 2
    if len(values) % 2:
        return values[mid]
    return sum(values[mid - 1:mid + 1]) / 2
