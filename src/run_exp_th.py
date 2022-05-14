import os

lst = os.listdir("conf_th")
print (lst)
#lst = [f for f in os.listdir("conf_th") if f[0] == "7" or f[0] == "8" or f[0] == "9" or f[0:2] == "10"]
lst = [f for f in os.listdir("conf_th") if f[0] == "3" or f[0] == "6"]
print (lst)

for t in range(1):
    print (">>>>> Trial: {} <<<<<".format(t))
    for conf in lst:
        tmp = conf.split(".")[0]
        s, c, e = tmp.split("_")
        print ("set: {}, cluster: {}, rules: {}".format(s, c, e))

        #cmd = "python3 run.py --bin apps/exp_th --conf conf_th/{}_{}_{}.conf >> /home/hwy/dpi-results/th/{}_{}_{}.txt".format(s, c, e, s, c, e)
        #cmd = "python3 run.py --bin apps/exp_th --conf conf_th/{}_{}_{}.conf".format(s, c, e)
        #os.system(cmd)
        #cmd = "echo "" >> /home/hwy/dpi-results/th/{}_{}_{}.txt".format(s, c, e)
        #os.system(cmd)

        #cmd = "python3 run.py --bin apps/exp_th --aes-ni --conf conf_th/{}_{}_{}.conf >> /home/hwy/dpi-results/th/{}_{}_{}_aes.txt".format(s, c, e, s, c, e)
        cmd = "python3 run.py --bin apps/exp_th --aes-ni --conf conf_th/{}_{}_{}.conf".format(s, c, e)
        os.system(cmd)
        cmd = "echo "" >> /home/hwy/dpi-results/th/{}_{}_{}_aes.txt".format(s, c, e)
        os.system(cmd)
