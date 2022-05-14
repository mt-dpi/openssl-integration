import logging
import json
import argparse
import base64
import time
import copy
import os

def average(lst):
    return round(sum(lst) / len(lst), 4)

def load_rules(rname):
    ret = set([])

    with open(rname, "rb") as f:
        for line in f:
            keyword = line.strip()
            ret.add(keyword)

    return ret

def load_data(content):
    return base64.b64decode(json.loads(content)["data"])

def analysis(rname, iname, ofname, wsize):
    rules = load_rules(rname)
    hit_rates = []
    tentries = []
    dlen = []
    idx = 0
    fexists = False

    if os.path.exists(ofname):
        fexists = True
        with open(ofname, "r") as f:
            for line in f:
                pass

        idx = int(line.strip().split(", ")[0])

    with open(ofname, "a") as of:
        if not fexists:
            of.write("index, data length, counter table entries, hit, miss, hit rate\n")

        with open(iname, "r") as f:
            if not fexists:
                cnt = 0
                for line in f:
                    cnt += 1
                    if cnt == idx:
                        break

            for line in f:
                hit = 0
                miss = 0
                idx += 1
                entries = []
                line = line.strip()
                data = load_data(line)

                for i in range(len(data) - wsize + 1):
                    window = data[i:i+8]
                    if window not in entries:
                        entries.append(window)

                    if window in rules:
                        hit += 1
                    else:
                        miss += 1
                hit_rate = hit / (hit + miss)
                #print ("data length: {} / counter table entries: {} / hit: {} / miss: {} / hit_rate: {}".format(len(data), len(entries), hit, miss, hit_rate))
                of.write("{}, {}, {}, {}, {}, {}\n".format(idx, len(data), len(entries), hit, miss, hit_rate))
                hit_rates.append(hit_rate)
                tentries.append(len(entries))
                dlen.append(len(data))

                if idx % 10000 == 0:
                    print (">>>>> index: {}".format(idx))
                    print ("  data length: avg: {}, min: {}, max: {}".format(average(dlen), min(dlen), max(dlen)))
                    print ("  hit rate: avg: {}\%, min: {}\%, max: {}\%".format(average(hit_rates) * 100, round(min(hit_rates), 4) * 100, round(max(hit_rates), 4) * 100))
                    print ("  counter table entries: avg: {}, min: {}, max: {}".format(average(tentries), min(tentries), max(tentries)))

        print ("data length: avg: {}, min: {}, max: {}".format(average(dlen), min(dlen), max(dlen)))
        of.write("data length: avg: {}, min: {}, max: {}\n".format(average(dlen), min(dlen), max(dlen)))
        print ("hit rate: avg: {}\%, min: {}\%, max: {}\%".format(average(hit_rates) * 100, round(min(hit_rates), 4) * 100, round(max(hit_rates), 4) * 100))
        of.write("hit rate: avg: {}\%, min: {}\%, max: {}\%\n".format(average(hit_rates) * 100, round(min(hit_rates), 4) * 100, round(max(hit_rates), 4) * 100))
        print ("counter table entries: avg: {}, min: {}, max: {}".format(average(tentries), min(tentries), max(tentries)))
        of.write("counter table entries: avg: {}, min: {}, max: {}\n".format(average(tentries), min(tentries), max(tentries)))

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--ruleset", metavar="<rule set>", help="rule set", type=str, required=True)
    parser.add_argument("-d", "--dataset", metavar="<input data set>", help="input data set", type=str, required=True)
    parser.add_argument("-o", "--output", metavar="<output file>", help="output file", type=str, default="output")
    parser.add_argument("-w", "--wsize", metavar="<window size>", help="window size", type=int, default=8)
    parser.add_argument("-l", "--log", metavar="<log-level (DEBUG/INFO/WARN/ERROR/CRITICAL)>", help="log-level (DEBUG/INFO/WARN/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logLevel = args.log
    logging.basicConfig(level=logLevel)
    rname = args.ruleset
    iname = args.dataset
    ofname = args.output
    wsize = args.wsize

    analysis(rname, iname, ofname, wsize)

if __name__ == "__main__":
    main()
