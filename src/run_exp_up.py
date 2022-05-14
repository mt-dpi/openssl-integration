import os

lst = os.listdir("conf_up")
print (lst)

for t in range(1):
    print (">>>>> Trial: {} <<<<<".format(t))
    for conf in lst:
        tmp = conf.split(".")[0]
        s, c, e = tmp.split("_")
        print ("set: {}, period: {}, rules: {}".format(s, c, e))

        cmd = "python3 run.py --bin apps/exp_up --conf conf_up/{}_{}_{}.conf >> /home/hwy/dpi-results/up3/{}_{}_{}.txt".format(s, c, e, s, c, e)
        os.system(cmd)
        cmd = "echo "" >> /home/hwy/dpi-results/up3/{}_{}_{}.txt".format(s, c, e)
        os.system(cmd)

        cmd = "python3 run.py --bin apps/exp_up --aes-ni --conf conf_up/{}_{}_{}.conf >> /home/hwy/dpi-results/up3/{}_{}_{}_aes.txt".format(s, c, e, s, c, e)
        os.system(cmd)
        cmd = "echo "" >> /home/hwy/dpi-results/up3/{}_{}_{}_aes.txt".format(s, c, e)
        os.system(cmd)
