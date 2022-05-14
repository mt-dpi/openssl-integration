import subprocess

lst = ["16k"]
up = [1, 200, 400, 600, 800, 1000, 1200, 1400, 1600]

for s in [3, 6]:
    for i in lst:
        for p in up:
            cmd = []
            cmd.append("python3")
            cmd.append("make_config_up_exp.py")
            cmd.append("-i")
            cmd.append("../data/inputs/input_8.html")
            cmd.append("-r")
            cmd.append("../data/rules/rule_8bytes_{}.txt".format(i))
            cmd.append("-o")
            cmd.append("conf_up/{}_{}_{}.conf".format(s, p, i))
            cmd.append("-p")
            cmd.append("16000")
            cmd.append("-q")
            cmd.append("{}".format(p))
            subprocess.call(cmd)
