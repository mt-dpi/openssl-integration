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
        rules = int(tmp[1])
        aes_ni = 0
        if len(tmp) == 3:
            aes_ni = 1

        if rules not in ret:
            ret[rules] = {}
            
        if conf not in ret[rules]:
            ret[rules][conf] = {}
        
        if aes_ni not in ret[rules][conf]:
            ret[rules][conf][aes_ni] = {}
            ret[rules][conf][aes_ni][k1] = []
            ret[rules][conf][aes_ni][k2] = []

        with open(fname, "r") as f:
            for line in f:
                line = line.strip()
                if len(line) < 1 or "AES-NI" in line:
                    continue
                k, v = line.strip()[:-3].split(": ")
                if k1 in k:
                    ret[rules][conf][aes_ni][k1].append(int(v))
                elif k2 in k:
                    ret[rules][conf][aes_ni][k2].append(int(v))

    return ret

def write_to_file(result, ofname):
    rlst = sorted(list(result.keys()))
    clst = [1, 2, 3, 4]
    alst = [0, 1]
    k1 = "token encryption"
    k2 = "token detection"

    with open(ofname, "w") as of:
        of.write("rules, conf, aes_ni, token encryption (trials), token encryption (mean), token encryption (stdev), token detection (trials), token detection (mean), token detection (stdev)\n")
        for r in rlst:
            for c in clst:
                for a in alst:
                    te = sorted(result[r][c][a][k1])[10:-10]
                    td = sorted(result[r][c][a][k2])[10:-10]
                    of.write("{}, {}, {}, {}, {}, {}, {}, {}, {}\n".format(r, c, a, len(te), round(average(te), 2), round(stdev(te), 2), len(td), round(average(td), 2), round(stdev(td), 2)))

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
