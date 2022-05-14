import subprocess

klst = ["16k"]
plst = [0, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000, 11000, 12000, 13000, 14000, 15000, 16000]

for s in [1, 3, 4, 6]:
    for i in klst:
        for p in plst:
            cmd = []
            cmd.append("python3")
            cmd.append("make_config_exp.py")
            cmd.append("-i")
            cmd.append("../data/inputs/input_8.html")
            cmd.append("-r")
            cmd.append("../data/rules/rule_8bytes_{}.txt".format(i))
            cmd.append("-o")
            cmd.append("conf/{}_{}_{}.conf".format(s, p, i))
            cmd.append("-p")
            cmd.append("{}".format(p))
            subprocess.call(cmd)
