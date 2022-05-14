import os
import time

lst = os.listdir("conf_td")
print (lst)
lst = ["3_1_16k.conf", "7_2_1k.conf", "7_2_2k.conf", "7_2_4k.conf", "7_2_8k.conf", "7_2_16k.conf", "7_2_32k.conf", "7_4_1k.conf", "7_4_2k.conf", "7_4_4k.conf", "7_4_8k.conf", "7_4_16k.conf", "7_4_32k.conf", "7_6_1k.conf", "7_6_2k.conf", "7_6_4k.conf", "7_6_8k.conf", "7_6_16k.conf", "7_6_32k.conf", "8_1_1k.conf", "8_1_2k.conf", "8_1_4k.conf", "8_1_8k.conf", "8_1_16k.conf", "8_1_32k.conf", "9_2_1k.conf", "9_2_2k.conf", "9_2_4k.conf", "9_2_8k.conf", "9_2_16k.conf", "9_2_32k.conf", "9_4_1k.conf", "9_4_2k.conf", "9_4_4k.conf", "9_4_8k.conf", "9_4_16k.conf", "9_4_32k.conf", "9_6_1k.conf", "9_6_2k.conf", "9_6_4k.conf", "9_6_8k.conf", "9_6_16k.conf", "9_6_32k.conf", "10_1_1k.conf", "10_1_2k.conf", "10_1_4k.conf", "10_1_8k.conf", "10_1_16k.conf", "10_1_32k.conf"]

for t in range(1):
    print (">>>>> Trial: {} <<<<<".format(t))
    for conf in lst:
        tmp = conf.split(".")[0]
        s, c, e = tmp.split("_")
        print ("set: {}, cluster: {}, rules: {}".format(s, c, e))

        #cmd = "python3 run.py --bin apps/exp_td_internal --conf conf_td/{}_{}_{}.conf >> /home/hwy/dpi-results/td4/{}_{}_{}.txt".format(s, c, e, s, c, e)
        #os.system(cmd)
        #cmd = "echo "" >> /home/hwy/dpi-results/td4/{}_{}_{}.txt".format(s, c, e)
        #os.system(cmd)

        cmd = "python3 run.py --bin apps/exp_td_internal --aes-ni --conf conf_td/{}_{}_{}.conf >> /home/hwy/dpi-results/td4/{}_{}_{}_aes.txt".format(s, c, e, s, c, e)
        os.system(cmd)
        cmd = "echo "" >> /home/hwy/dpi-results/td4/{}_{}_{}_aes.txt".format(s, c, e)
        os.system(cmd)

        time.sleep(1)
