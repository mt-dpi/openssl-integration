import os

lst = os.listdir("conf_tu")
print (lst)

for t in range(1):
    print (">>>>> Trial: {} <<<<<".format(t))
    for conf in lst:
        tmp = conf.split(".")[0]
        s, c, e = tmp.split("_")
        print ("set: {}, cluster: {}, rules: {}".format(s, c, e))

        cmd = "python3 run.py --bin apps/exp_tu_internal --conf conf_tu/{}_{}_{}.conf >> /home/hwy/dpi-results/tu2/{}_{}_{}.txt".format(s, c, e, s, c, e)
        os.system(cmd)
        cmd = "echo "" >> /home/hwy/dpi-results/tu2/{}_{}_{}.txt".format(s, c, e)
        os.system(cmd)

        cmd = "python3 run.py --bin apps/exp_tu_internal --aes-ni --conf conf_tu/{}_{}_{}.conf >> /home/hwy/dpi-results/tu2/{}_{}_{}_aes.txt".format(s, c, e, s, c, e)
        os.system(cmd)
        cmd = "echo "" >> /home/hwy/dpi-results/tu2/{}_{}_{}_aes.txt".format(s, c, e)
        os.system(cmd)
