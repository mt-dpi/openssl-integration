import logging
import json
import argparse
import base64
import time

def extract(fname, num, prefix):
    ret = {}

    with open(fname, "r") as f:
        for line in f:
            counter = {}
            num -= 1
            if num == 0:
                break
            js = json.loads(line)
            document = base64.b64decode(js["data"].encode())
            with open("{}_{}.html".format(prefix, num), "wb") as of:
                of.write(document)
            
    return ret

def write_to_file(ofname, result):
    with open(ofname, "w") as of:
        for k in result:
            of.write("{}, {}\n".format(k, result[k]))

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dataset", metavar="<dataset>", help="dataset", type=str, required=True)
    parser.add_argument("-n", "--number", metavar="<number of documents>", help="number of documents", type=int, required=True)
    parser.add_argument("-o", "--output", metavar="<output file name prefix>", help="output file name prefix", type=str, default="output")
    parser.add_argument("-l", "--log", metavar="<log-level (DEBUG/INFO/WARN/ERROR/CRITICAL)>", help="log-level (DEBUG/INFO/WARN/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logLevel = args.log
    logging.basicConfig(level=logLevel)
    fname = args.dataset
    num = args.number
    prefix = args.output

    result = extract(fname, num, prefix)

if __name__ == "__main__":
    main()
