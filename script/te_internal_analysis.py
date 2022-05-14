import argparse
import sys
import os
import math

def average(lst):
    if len(lst) == 0:
        return 0
    return sum(lst)/len(lst)

def stdev(lst):
    squares = []
    for elem in lst:
        squares.append(elem * elem)
    var = average(squares) - average(lst) **2
    return math.sqrt(var)

def analysis(directory):
    ret = {}
    flst = [ "{}/{}".format(directory, f) for f in os.listdir(directory) if "aes.txt" in f]

    for fname in flst:
        tmp = fname.split("/")[1].split(".")[0].split("_")
        conf = int(tmp[0])
        clusters = int(tmp[1])
        entries = int(tmp[2])
        aes_ni = 0
        if len(tmp) == 4:
            aes_ni = 1

        if conf not in ret:
            ret[conf] = {}

        if clusters not in ret[conf]:
            ret[conf][clusters] = {}

        if entries not in ret[conf][clusters]:
            ret[conf][clusters][entries] = {}

        with open(fname, "r") as f:
            for line in f:
                tmp = line.strip().split(": ")
                if len(tmp) < 2:
                    continue
                k = tmp[0]
                v = tmp[1]

                if k not in ret[conf][clusters][entries]:
                    ret[conf][clusters][entries][k] = []

                val = float(v[:-2])
                ret[conf][clusters][entries][k].append(val)

    print (ret)
    return ret

def write_to_file(result, ofname):
    nes = [0, 1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000]
    keys = ["total", "counter value", "others 1", "others 2", "others 3", "others 4", "aes 1", "aes 2", "aes 3", "aes 4", "xor 1", "xor 2", "xor 3", "xor 4", "aes init"]

    with open(ofname, "w") as of:
        of.write("conf, # of clusters, key, 0, 1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000\n")
        for conf in range(1, 7):
            clst = sorted(list(result[conf].keys()))
            for clusters in clst:
                for key in keys:
                    if key in result[conf][clusters][1000]:
                        of.write("{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}\n".format(conf, clusters, key, average(result[conf][clusters][0][key]), average(result[conf][clusters][1000][key]), average(result[conf][clusters][2000][key]), average(result[conf][clusters][4000][key]), average(result[conf][clusters][8000][key]), average(result[conf][clusters][16000][key]), average(result[conf][clusters][32000][key]), average(result[conf][clusters][64000][key]), average(result[conf][clusters][128000][key])))

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", metavar='<directory>',
                        help='directory', default=".")
    parser.add_argument("-o", "--output", metavar='<output file>',
                        help='output file', default="output.csv")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    ret = analysis(args.directory)
    write_to_file(ret, args.output)

if __name__ == '__main__':
    main()
