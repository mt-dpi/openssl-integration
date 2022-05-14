import subprocess

lst = ["1k", "2k", "4k", "8k", "16k", "32k"]

for s in [1, 3, 4, 6, 8, 10]:
    for i in lst:
        cmd = []
        cmd.append("python3")
        cmd.append("make_config_td_exp.py")
        cmd.append("-i")
        cmd.append("../data/inputs/input_tu.html")
        cmd.append("-r")
        cmd.append("../data/rules/rule_8bytes_{}.txt".format(i))
        cmd.append("-o")
        cmd.append("conf_th/{}_1_{}.conf".format(s, i))
        cmd.append("-p")
        cmd.append("16000")
        subprocess.call(cmd)

for s in [2, 5, 7, 9]:
    for c in [2, 4, 6]:
        for i in lst:
            cmd = []
            cmd.append("python3")
            cmd.append("make_config_td_exp.py")
            cmd.append("-i")
            cmd.append("../data/inputs/input_tu.html")
            cmd.append("-r")
            cmd.append("../data/rules/rule_8bytes_{}.txt".format(i))
            cmd.append("-o")
            cmd.append("conf_th/{}_{}_{}.conf".format(s, c, i))
            cmd.append("-n")
            cmd.append("{}".format(c))
            cmd.append("-p")
            cmd.append("16000")
            subprocess.call(cmd)
