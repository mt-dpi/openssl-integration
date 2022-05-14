import subprocess

for s in [1, 4]:
    i = "16k"
    cmd = []
    cmd.append("python3")
    cmd.append("make_config_td_exp.py")
    cmd.append("-i")
    cmd.append("../data/inputs/input_td.html")
    cmd.append("-r")
    cmd.append("../data/rules/rule_8bytes_{}.txt".format(i))
    cmd.append("-o")
    cmd.append("conf_td/{}_1_{}.conf".format(s, i))
    cmd.append("-p")
    cmd.append("0")
    subprocess.call(cmd)
