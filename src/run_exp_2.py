import os

klst = ["1k", "2k", "4k", "8k", "16k", "32k"]
plst = [16000]


for t in range(10):
    print (">>>>> Trial: {} <<<<<".format(t))
    for s in [1, 3, 4, 6]:
        for i in klst:
            for p in plst:
                print("s: {}, i: {}, p: {}".format(s, p, i))
                cmd = "python3 run.py --bin apps/exp_local_once --conf conf/{}_{}_{}.conf >> /home/hwy/dpi-results/td1/{}_{}_{}.txt".format(s, p, i, s, p, i)
                os.system(cmd)
                cmd = "echo "" >> /home/hwy/dpi-results/td1/{}_{}_{}.txt".format(s, p, i)
                os.system(cmd)

                cmd = "python3 run.py --bin apps/exp_local_once --aes-ni --conf conf/{}_{}_{}.conf >> /home/hwy/dpi-results/td1/{}_{}_{}_aes.txt".format(s, p, i, s, p, i)
                os.system(cmd)
                cmd = "echo "" >> /home/hwy/dpi-results/td1/{}_{}_{}_aes.txt".format(s, p, i)
                os.system(cmd)
