import subprocess

lst = ["1k", "2k", "3k", "4k", "5k", "6k", "7k", "8k", "9k", "10k", "11k", "12k", "13k", "14k", "15k", "16k", "17k", "18k", "19k", "20k", "21k", "22k", "23k", "24k", "25k", "26k", "27k", "28k", "29k", "30k", "31k", "32k"]

for s in [1, 3, 4, 6, 8, 10]:
    for i in lst:
        cmd = []
        cmd.append("python3")
        cmd.append("make_config_exp.py")
        cmd.append("-i")
        cmd.append("../data/inputs/input_8.html")
        cmd.append("-r")
        cmd.append("../data/rules/rule_8bytes_{}.txt".format(i))
        cmd.append("-o")
        cmd.append("conf/{}_1_{}.conf".format(s, i))
        subprocess.call(cmd)

for s in [2, 5, 7, 9]:
    for c in [2, 4, 6]:
        for i in lst:
            cmd = []
            cmd.append("python3")
            cmd.append("make_config_exp.py")
            cmd.append("-i")
            cmd.append("../data/inputs/input_8.html")
            cmd.append("-r")
            cmd.append("../data/rules/rule_8bytes_{}.txt".format(i))
            cmd.append("-o")
            cmd.append("conf/{}_{}_{}.conf".format(s, c, i))
            cmd.append("-n")
            cmd.append("{}".format(c))
            subprocess.call(cmd)
