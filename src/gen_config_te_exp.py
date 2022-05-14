import subprocess

plst = [0, 1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000]
clusters = {}
clusters[1] = [1]
clusters[2] = [2, 4, 6]
clusters[3] = [1]
clusters[4] = [1]
clusters[5] = [2, 4, 6]
clusters[6] = [1]

for s in [1, 4]:
    c = 1
    p = 0
    cmd = []
    cmd.append("python3")
    cmd.append("make_config_te_exp.py")
    cmd.append("-o")
    cmd.append("conf_te/{}_{}_{}.conf".format(s, c, p))
    cmd.append("-p")
    cmd.append("{}".format(p))
    cmd.append("-n")
    cmd.append("{}".format(c))
    subprocess.call(cmd)
