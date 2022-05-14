import sys

with open(sys.argv[1], "r") as f:
    total = 0.0
    title = None

    for line in f:
        if "Fixed key detection" in line:
            title = line.strip()
            total = 0.0
        elif "Non-fixed key detection" in line:
            title = line.strip()
            total = 0.0
        elif "Time" in line:
            tmp = line.strip().split(":")[-1].strip().split(" ")[0].strip()
            val = float(tmp)
            total += val
        else:
            print ("{} {:.2f} ns".format(title, total))

