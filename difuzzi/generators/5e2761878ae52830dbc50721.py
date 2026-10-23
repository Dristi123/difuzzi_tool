def generate(fdp):
    n = fdp.ConsumeIntInRange(1, 20)  # non-empty list, max 20 elements
    xs = []
    for _ in range(n):
        if fdp.ConsumeBool():
            xs.append(fdp.ConsumeIntInRange(-1000, 1000))
        else:
            xs.append(fdp.ConsumeFloatInRange(-1000.0, 1000.0))
    return (xs,)
