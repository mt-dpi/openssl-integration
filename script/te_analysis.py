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

        with open(fname, "r") as f:
            for line in f:
                tmp = line.strip().split(": ")
                if len(tmp) < 2:
                    continue
                k = tmp[0]
                v = tmp[1]

                if "ns" in v:
                    val = float(v[:-2])
                elif "counter table" in k:
                    val = int(v)
                    if val != entries:
                        print ("fname: {}".format(fname))
                        raise ValueError
                else:
                    val = v

                if "(token_encryption)" in k:
                    ret[conf][clusters][entries] = val

    print (ret)
    return ret

def write_to_file(result, ofname):
    nes = [10, 100, 1000, 10000, 100000]

    with open(ofname, "w") as of:
        of.write("conf, # of clusters, 10, 100, 1000, 10000, 100000\n")
        for conf in range(1, 7):
            clst = sorted(list(result[conf].keys()))
            for clusters in clst:
                of.write("{}, {}, {}, {}, {}, {}, {}\n".format(conf, clusters, result[conf][clusters][10], result[conf][clusters][100], result[conf][clusters][1000], result[conf][clusters][10000], result[conf][clusters][100000]))

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
