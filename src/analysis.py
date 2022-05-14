import sys

with open(sys.argv[1], "r") as f:
    total = 0.0

    for line in f:
        if "Fixed key encryption" in line:
            print ("Non-fixed key encryption Total: {} ns".format(total))
            total = 0.0
        elif "Non-fixed key encryption" in line:
            print ("Fixed key encryption Total: {} ns".format(total))
            total = 0.0
        elif "Result" in line:
            print ("Non-fixed key encryption Total: {} ns".format(total))
        else:
            if "Time" not in line:
                continue
            tmp = line.strip().split(":")[-1].strip().split(" ")[0].strip()
            val = float(tmp)
            total += val
