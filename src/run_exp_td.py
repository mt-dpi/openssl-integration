import os

lst = os.listdir("conf_td")
print (lst)

for t in range(1):
    print (">>>>> Trial: {} <<<<<".format(t))
    for conf in lst:
        tmp = conf.split(".")[0]
        s, c, e = tmp.split("_")
        print ("set: {}, cluster: {}, rules: {}".format(s, c, e))

        #cmd = "python3 run.py --bin apps/exp_td --conf conf_td/{}_{}_{}.conf >> /home/hyun/dpi-results/td5/{}_{}_{}.txt".format(s, c, e, s, c, e)
        #cmd = "python3 run.py --bin apps/exp_td --conf conf_td/{}_{}_{}.conf".format(s, c, e)
        #os.system(cmd)
        #cmd = "echo "" >> /home/hyun/dpi-results/td5/{}_{}_{}.txt".format(s, c, e)
        #os.system(cmd)

        cmd = "python3 run.py --bin apps/exp_td --aes-ni --conf conf_td/{}_{}_{}.conf".format(s, c, e)
        print (cmd)
        os.system(cmd)
        #cmd = "echo "" >> /home/hyun/dpi-results/td5/{}_{}_{}_aes.txt".format(s, c, e)
        #os.system(cmd)
