import os

lst = os.listdir("conf_cache")
print (lst)

for t in range(1):
    print (">>>>> Trial: {} <<<<<".format(t))
    for conf in lst:
        print (">>>>> Conf: {} <<<<<".format(conf))
        cmd = "echo {} >> cache_result".format(conf)
        os.system(cmd)

        cmd = "python3 run.py --bin apps/cache --conf conf_cache/{} --aes".format(conf)
        os.system(cmd)
