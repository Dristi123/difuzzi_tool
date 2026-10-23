def generate(fdp):
    n = fdp.ConsumeIntInRange(0, 20)
    xs = sorted(set(fdp.ConsumeIntInRange(-1000, 1000) for _ in range(n)))
    if xs and fdp.ConsumeBool():
        t = fdp.PickValueInList(xs)
    else:
        t = fdp.ConsumeIntInRange(-1000, 1000)
    return (xs, t)
