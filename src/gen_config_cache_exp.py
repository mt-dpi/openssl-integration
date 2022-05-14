import subprocess

plst = [0, 1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000, 256000]

for s in [1, 3, 4, 6]:
    for p in plst:
        cmd = []
        cmd.append("python3")
        cmd.append("make_config_cache_exp.py")
        cmd.append("-o")
        cmd.append("conf_cache/{}_{}.conf".format(s, p))
        cmd.append("-p")
        cmd.append("{}".format(p))
        subprocess.call(cmd)
