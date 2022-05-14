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
    flst = [ "{}/{}".format(directory, f) for f in os.listdir(directory) if ".txt" in f]

    k1 = "token encryption"
    k2 = "token detection"

    for fname in flst:
        tmp = fname.split("/")[1].split(".")[0].split("_")
        conf = int(tmp[0])
        entries = int(tmp[1])
        rules = tmp[2]
        aes_ni = 0
        if len(tmp) == 4:
            aes_ni = 1

        if rules not in ret:
            ret[rules] = {}
            
        if conf not in ret[rules]:
            ret[rules][conf] = {}

        if entries not in ret[rules][conf]:
            ret[rules][conf][entries] = {}
        
        if aes_ni not in ret[rules][conf][entries]:
            ret[rules][conf][entries][aes_ni] = {}
            ret[rules][conf][entries][aes_ni][k1] = {}
            ret[rules][conf][entries][aes_ni][k2] = {}
            ret[rules][conf][entries][aes_ni][k1]["found"] = []
            ret[rules][conf][entries][aes_ni][k1]["not found"] = []
            ret[rules][conf][entries][aes_ni][k2]["found"] = []
            ret[rules][conf][entries][aes_ni][k2]["not found"] = []

        found = False
        with open(fname, "r") as f:
            for line in f:
                line = line.strip()
                if len(line) < 1 or "AES-NI" in line:
                    continue
                k, v = line.strip()[:-3].split(": ")
                if k1 in k:
                    if found:
                        ret[rules][conf][entries][aes_ni][k1]["found"].append(int(v))
                    else:
                        ret[rules][conf][entries][aes_ni][k1]["not found"].append(int(v))
                elif k2 in k:
                    if found:
                        ret[rules][conf][entries][aes_ni][k2]["found"].append(int(v))
                        found = False
                    else:
                        ret[rules][conf][entries][aes_ni][k2]["not found"].append(int(v))
                        found = True

    print (ret)
    return ret

def write_to_file(result, ofname):
    rlst = ["16k"]
    clst = [1, 3, 4, 6]
    nelst = [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000, 11000, 12000, 13000, 14000, 15000, 16000]
    alst = [0, 1]
    k1 = "token encryption"
    k2 = "token detection"

    with open(ofname, "w") as of:
        of.write("# of tokens, conf, # of clusters, aes_ni, detected, token encryption (trials), token encryption (mean), token encryption (stdev), token detection (trials), token detection (mean), token detection (stdev)\n")
        for r in rlst:
            for c in clst:
                for ne in nelst:
                    for a in alst:
                        tef = sorted(result[r][c][ne][a][k1]["found"])
                        tenf = sorted(result[r][c][ne][a][k1]["not found"])
                        tdf = sorted(result[r][c][ne][a][k2]["found"])
                        tdnf = sorted(result[r][c][ne][a][k2]["not found"])
                        of.write("{}, {}, {}, {}, true, {}, {}, {}, {}, {}, {}\n".format(r, c, ne, a, len(tef), round(average(tef), 2), round(stdev(tef), 2), len(tdf), round(average(tdf), 2), round(stdev(tdf), 2)))
                        of.write("{}, {}, {}, {}, false, {}, {}, {}, {}, {}, {}\n".format(r, c, ne, a, len(tenf), round(average(tenf), 2), round(stdev(tenf), 2), len(tdnf), round(average(tdnf), 2), round(stdev(tdnf), 2)))

    with open(ofname, "a") as of:
        of.write("\n\nToken Encryption\n")
        of.write("conf, ")
        for ne in nelst[:-1]:
            of.write("{}, ".format(ne))
        of.write("{}\n".format(nelst[-1]))

        for c in clst:
            of.write("{}, ".format(c))
            for ne in nelst[:-1]:
                of.write("{}, ".format(average(result["16k"][c][ne][1][k1]["found"])))
            of.write("{}\n".format(average(result["16k"][c][ne][1][k1]["found"])))

    with open(ofname, "a") as of:
        of.write("\n\nToken Detection\n")
        of.write("conf, ")
        for ne in nelst[:-1]:
            of.write("{}, ".format(ne))
        of.write("{}\n".format(nelst[-1]))

        for c in clst:
            of.write("{}, ".format(c))
            for ne in nelst[:-1]:
                of.write("{}, ".format(average(result["16k"][c][ne][1][k2]["found"])))
            of.write("{}\n".format(average(result["16k"][c][ne][1][k2]["found"])))


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
