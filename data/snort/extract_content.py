import logging
import json
import argparse
import base64
import time

def convert(content, wsize):
    ret = []

    ascii_start = False
    lst = []
    ch = ""
    for c in content:
        if c == "|":
            ascii_start = True
            continue

        if c == "\"":
            continue

        if c == " ":
            continue

        if not ascii_start:
            lst.append(c.encode())
        else:
            ch += c
            lst.append(bin(int(ch, 16)))
            ch = ""

    print ("lst: {}".format(lst))

    return ret

def extract(fname, ofname, wsize):
    with open(ofname, "wb") as of:
        with open(fname, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
            
                tmp = line.strip().split(";")
                for e in tmp:
                    if "content" in e:
                        content = e.split(":")[1].split(",")[0]
                        wlst = convert(content, wsize)
                        for word in wlst:
                            of.write("{}\n".format(word))

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--ruleset", metavar="<rule set>", help="rule set", type=str, required=True)
    parser.add_argument("-o", "--output", metavar="<output file>", help="output file", type=str, default="output")
    parser.add_argument("-w", "--wsize", metavar="<window size>", help="window size", type=int, default=8)
    parser.add_argument("-l", "--log", metavar="<log-level (DEBUG/INFO/WARN/ERROR/CRITICAL)>", help="log-level (DEBUG/INFO/WARN/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logLevel = args.log
    logging.basicConfig(level=logLevel)
    fname = args.ruleset
    ofname = args.output
    wsize = args.wsize

    result = extract(fname, ofname, wsize)

if __name__ == "__main__":
    main()
