import os

lst = os.listdir("conf_te")
print (lst)

for t in range(1):
    print (">>>>> Trial: {} <<<<<".format(t))
    for conf in lst:
        tmp = conf.split(".")[0]
        s, c, e = tmp.split("_")
        print ("set: {}, cluster: {}, entries: {}".format(s, c, e))

        #cmd = "python3 run.py --bin apps/exp_te --conf conf_te/{}_{}_{}.conf >> /home/hyun/dpi-results/token_encryption/{}_{}_{}.txt".format(s, c, e, s, c, e)
#        cmd = "python3 run.py --bin apps/exp_te --conf conf_te/{}_{}_{}.conf".format(s, c, e)
#        os.system(cmd)
        #cmd = "echo "" >> /home/hyun/dpi-results/token_encryption/{}_{}_{}.txt".format(s, c, e)
        #os.system(cmd)

        #cmd = "python3 run.py --bin apps/exp_te --aes-ni --conf conf_te/{}_{}_{}.conf >> /home/hyun/dpi-results/token_encryption/{}_{}_{}_aes.txt".format(s, c, e, s, c, e)
        cmd = "python3 run.py --bin apps/exp_te --aes-ni --conf conf_te/{}_{}_{}.conf".format(s, c, e)
        os.system(cmd)
        #cmd = "echo "" >> /home/hyun/dpi-results/token_encryption/{}_{}_{}_aes.txt".format(s, c, e)
        #os.system(cmd)
