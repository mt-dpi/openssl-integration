import argparse
import sys
import os
import math

def average(lst):
    if len(lst) == 0:
        return 0
    lst = sorted(lst)
    pivot = int(len(lst) * 0.1)
    lst = lst[pivot:len(lst)-pivot]
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
        period = int(tmp[1])
        entries = tmp[2]
        aes_ni = 0
        if len(tmp) == 4:
            aes_ni = 1

        if conf not in ret:
            ret[conf] = {}

        if period not in ret[conf]:
            ret[conf][period] = {}

        if entries not in ret[conf][period]:
            ret[conf][period][entries] = {}

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

                if "(found) (token_detection)" in k:
                    ret[conf][period][entries]["found"] = val

                if "(not found) (token_detection)" in k:
                    ret[conf][period][entries]["not found"] = val

    print (ret)
    return ret

def write_to_file(result, ofname):
    with open(ofname, "w") as of:
        of.write("conf, 1, 200, 400, 600, 800, 1000\n")
        for conf in [3, 6]:
            of.write("{}, {}, {}, {}, {}, {}, {}\n".format(conf, result[conf][1]["16k"]["found"], result[conf][200]["16k"]["found"], result[conf][400]["16k"]["found"], result[conf][600]["16k"]["found"], result[conf][800]["16k"]["found"], result[conf][1000]["16k"]["found"]))
        of.write("\n")

    with open(ofname, "a") as of:
        of.write("conf, 1, 200, 400, 600, 800, 1000\n")
        for conf in [3, 6]:
            of.write("{}, {}, {}, {}, {}, {}, {}\n".format(conf, result[conf][1]["16k"]["not found"], result[conf][200]["16k"]["not found"], result[conf][400]["16k"]["not found"], result[conf][600]["16k"]["not found"], result[conf][800]["16k"]["not found"], result[conf][1000]["16k"]["not found"]))

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
