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
        ncluster = int(tmp[1])
        rules = tmp[2]
        aes_ni = 0
        if len(tmp) == 4:
            aes_ni = 1

        if rules not in ret:
            ret[rules] = {}
            
        if conf not in ret[rules]:
            ret[rules][conf] = {}

        if ncluster not in ret[rules][conf]:
            ret[rules][conf][ncluster] = {}
        
        if aes_ni not in ret[rules][conf][ncluster]:
            ret[rules][conf][ncluster][aes_ni] = {}
            ret[rules][conf][ncluster][aes_ni][k1] = {}
            ret[rules][conf][ncluster][aes_ni][k2] = {}
            ret[rules][conf][ncluster][aes_ni][k1]["found"] = []
            ret[rules][conf][ncluster][aes_ni][k1]["not found"] = []
            ret[rules][conf][ncluster][aes_ni][k2]["found"] = []
            ret[rules][conf][ncluster][aes_ni][k2]["not found"] = []

        found = False
        with open(fname, "r") as f:
            for line in f:
                line = line.strip()
                if len(line) < 1 or "AES-NI" in line:
                    continue
                k, v = line.strip()[:-3].split(": ")
                if k1 in k:
                    if found:
                        ret[rules][conf][ncluster][aes_ni][k1]["found"].append(int(v))
                    else:
                        ret[rules][conf][ncluster][aes_ni][k1]["not found"].append(int(v))
                elif k2 in k:
                    if found:
                        ret[rules][conf][ncluster][aes_ni][k2]["found"].append(int(v))
                        found = False
                    else:
                        ret[rules][conf][ncluster][aes_ni][k2]["not found"].append(int(v))
                        found = True

    return ret

def write_to_file(result, ofname):
    rlst = ["1k", "2k", "3k", "4k", "5k", "6k", "7k", "8k", "9k", "10k", "11k", "12k", "13k", "14k", "15k", "16k", "17k", "18k", "19k", "20k", "21k", "22k", "23k", "24k", "25k", "26k", "27k", "28k", "29k", "30k", "31k", "32k"]
    clst = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    nclst = [2, 4, 6]
    alst = [0, 1]
    k1 = "token encryption"
    k2 = "token detection"

    with open(ofname, "w") as of:
        of.write("# of tokens, conf, # of clusters, aes_ni, detected, token encryption (trials), token encryption (mean), token encryption (stdev), token detection (trials), token detection (mean), token detection (stdev)\n")
        for r in rlst:
            for c in clst:
                if c in [2, 5, 7, 9]:
                    for nc in [2, 4, 6]:
                        for a in alst:
                            tef = sorted(result[r][c][nc][a][k1]["found"])
                            tenf = sorted(result[r][c][nc][a][k1]["not found"])
                            tdf = sorted(result[r][c][nc][a][k2]["found"])
                            tdnf = sorted(result[r][c][nc][a][k2]["not found"])
                            of.write("{}, {}, {}, {}, true, {}, {}, {}, {}, {}, {}\n".format(r, c, nc, a, len(tef), round(average(tef), 2), round(stdev(tef), 2), len(tdf), round(average(tdf), 2), round(stdev(tdf), 2)))
                            of.write("{}, {}, {}, {}, false, {}, {}, {}, {}, {}, {}\n".format(r, c, nc, a, len(tenf), round(average(tenf), 2), round(stdev(tenf), 2), len(tdnf), round(average(tdnf), 2), round(stdev(tdnf), 2)))
                else:
                    for a in alst:
                        tef = sorted(result[r][c][1][a][k1]["found"])
                        tenf = sorted(result[r][c][1][a][k1]["not found"])
                        tdf = sorted(result[r][c][1][a][k2]["found"])
                        tdnf = sorted(result[r][c][1][a][k2]["not found"])
                        of.write("{}, {}, 1, {}, true, {}, {}, {}, {}, {}, {}\n".format(r, c, a, len(tef), round(average(tef), 2), round(stdev(tef), 2), len(tdf), round(average(tdf), 2), round(stdev(tdf), 2)))
                        of.write("{}, {}, 1, {}, false, {}, {}, {}, {}, {}, {}\n".format(r, c, a, len(tenf), round(average(tenf), 2), round(stdev(tenf), 2), len(tdnf), round(average(tdnf), 2), round(stdev(tdnf), 2)))

    nc = 0
    with open(ofname, "a") as of:
        of.write("\n\nToken Encryption\n")
        of.write("conf, cluster, ")
        for r in rlst[:-1]:
            of.write("{}, ".format(r))
        of.write("{}\n".format(r))

        for c in clst:
            cluster = 0
            while cluster < 5 and cluster % 2 == 0:
                if c not in [2, 5, 7, 9]:
                    cluster = 1
                else:
                    cluster = cluster + 2

                if c not in [2, 5, 7, 9]:
                    of.write("{}, 1, ".format(c))
                else:
                    of.write("{}, {}, ".format(c, cluster))

                for r in rlst[:-1]:
                    of.write("{}, ".format(average(result[r][c][cluster][1][k1]["found"])))
                of.write("{}\n".format(average(result[rlst[-1]][c][cluster][1][k1]["found"])))

    with open(ofname, "a") as of:
        of.write("\n\nToken Detection\n")
        of.write("conf, cluster, ")
        for r in rlst[:-1]:
            of.write("{}, ".format(r))
        of.write("{}\n".format(r))

        for c in clst:
            cluster = 0
            while cluster < 5 and cluster % 2 == 0:
                if c not in [2, 5, 7, 9]:
                    cluster = 1
                else:
                    cluster = cluster + 2

                if c not in [2, 5, 7, 9]:
                    of.write("{}, 1, ".format(c))
                else:
                    of.write("{}, {}, ".format(c, cluster))


                for r in rlst[:-1]:
                    of.write("{}, ".format(average(result[r][c][cluster][1][k2]["found"])))
                of.write("{}\n".format(average(result[rlst[-1]][c][cluster][1][k2]["found"])))

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
