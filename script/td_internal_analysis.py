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
    keys = ["others 1", "others 2", "search", "update", "total"]

    for fname in flst:
        tmp = fname.split("/")[1].split(".")[0].split("_")
        conf = int(tmp[0])
        clusters = int(tmp[1])
        rule = tmp[2]
        aes_ni = 0
        if len(tmp) == 4:
            aes_ni = 1

        if conf not in ret:
            ret[conf] = {}

        if clusters not in ret[conf]:
            ret[conf][clusters] = {}

        if rule not in ret[conf][clusters]:
            ret[conf][clusters][rule] = {}
            ret[conf][clusters][rule]["found"] = {}
            ret[conf][clusters][rule]["not found"] = {}

            for key in keys:
                ret[conf][clusters][rule]["found"][key] = []
                ret[conf][clusters][rule]["not found"][key] = []

        count = 0
        rcount = 0
        with open(fname, "r") as f:
            for line in f:
                tmp = line.strip().split(": ")
                if len(tmp) < 2:
                    count += 1
                    rcount = 0
                    continue

                if count >= 2 and rcount < 100:
                    k = tmp[0]

                    if "Result" in k:
                        rcount += 1
                        continue

                    v = tmp[1]

                    if k not in ret[conf][clusters][rule]:
                        ret[conf][clusters][rule][k] = []
    
                    val = float(v[:-2])
                    if count == 2:
                        ret[conf][clusters][rule]["not found"][k].append(val)
                    if count == 3:
                        ret[conf][clusters][rule]["found"][k].append(val)

    print (ret)
    return ret

def write_to_file(result, ofname):
    keys = ["total", "search", "update"]

    with open(ofname, "w") as of:
        of.write("conf, # of clusters, key, 1k (found), 2k (found), 4k (found), 8k (found), 16k (found), 32k (found)\n")
        for conf in range(1, 11):
            clst = sorted(list(result[conf].keys()))
            for clusters in clst:
                for key in keys:
                    of.write("{}, {}, {}, {}, {}, {}, {}, {}, {}\n".format(conf, clusters, key, average(result[conf][clusters]["1k"]["found"][key]), average(result[conf][clusters]["2k"]["found"][key]), average(result[conf][clusters]["4k"]["found"][key]), average(result[conf][clusters]["8k"]["found"][key]), average(result[conf][clusters]["16k"]["found"][key]), average(result[conf][clusters]["32k"]["found"][key])))

    with open(ofname, "a") as of:
        of.write("conf, # of clusters, key, 1k (not found), 2k (not found), 4k (not found), 8k (not found), 16k (not found), 32k (not found)\n")
        for conf in range(1, 11):
            clst = sorted(list(result[conf].keys()))
            for clusters in clst:
                for key in keys:
                    of.write("{}, {}, {}, {}, {}, {}, {}, {}, {}\n".format(conf, clusters, key, average(result[conf][clusters]["1k"]["not found"][key]), average(result[conf][clusters]["2k"]["not found"][key]), average(result[conf][clusters]["4k"]["not found"][key]), average(result[conf][clusters]["8k"]["not found"][key]), average(result[conf][clusters]["16k"]["not found"][key]), average(result[conf][clusters]["32k"]["not found"][key])))

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
