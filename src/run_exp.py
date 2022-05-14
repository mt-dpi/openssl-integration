import os

lst = ["1k", "2k", "3k", "4k", "5k", "6k", "7k", "8k", "9k", "10k", "11k", "12k", "13k", "14k", "15k", "16k", "17k", "18k", "19k", "20k", "21k", "22k", "23k", "24k", "25k", "26k", "27k", "28k", "29k", "30k", "31k", "32k"]


for t in range(10):
    print (">>>>> Trial: {} <<<<<".format(t))
    for s in [1, 3, 4, 6, 8, 10]:
        for i in lst:
            print("s: {}, c: 1, i: {}".format(s, i))
            cmd = "python3 run.py --bin apps/exp_local_once --conf conf/{}_1_{}.conf >> /home/hwy/dpi-results/3/{}_1_{}.txt".format(s, i, s, i)
            os.system(cmd)
            cmd = "echo "" >> /home/hwy/dpi-results/3/{}_1_{}.txt".format(s, i)
            os.system(cmd)

            cmd = "python3 run.py --bin apps/exp_local_once --aes-ni --conf conf/{}_1_{}.conf >> /home/hwy/dpi-results/3/{}_1_{}_aes.txt".format(s, i, s, i)
            os.system(cmd)
            cmd = "echo "" >> /home/hwy/dpi-results/3/{}_1_{}_aes.txt".format(s, i)
            os.system(cmd)

    for s in [2, 5, 7, 9]:
        for c in [2, 4, 6]:
            for i in lst:
                print("s: {}, c: {}, i: {}".format(s, c, i))
                cmd = "python3 run.py --bin apps/exp_local_once --conf conf/{}_{}_{}.conf >> /home/hwy/dpi-results/3/{}_{}_{}.txt".format(s, c, i, s, c, i)
                os.system(cmd)
                cmd = "echo "" >> /home/hwy/dpi-results/3/{}_{}_{}.txt".format(s, c, i)
                os.system(cmd)

                cmd = "python3 run.py --bin apps/exp_local_once --aes-ni --conf conf/{}_{}_{}.conf >> /home/hwy/dpi-results/3/{}_{}_{}_aes.txt".format(s, c, i, s, c, i)
                os.system(cmd)
                cmd = "echo "" >> /home/hwy/dpi-results/3/{}_{}_{}_aes.txt".format(s, c, i)
                os.system(cmd)
