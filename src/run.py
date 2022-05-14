import argparse
import sys
import os
import logging
import subprocess

def parse_index_file(fname):
    ret = {}
    
    with open(fname, "r") as f:
        for line in f:
            if "_IDX" not in line:
                continue

            idx = line.index(" ")
            line = line[idx:].strip()
            tmp = line.strip().split(" ")

            while '' in tmp:
                tmp.remove('')

            key = tmp[0]
            val = int(tmp[1])

            ret[key] = val
    return ret  

def parse_config(cname, idxes):
    ret = {}

    with open(cname, "r") as f:
        for line in f:
            if line[0] == "#":
                continue

            if line.strip() == "":
                continue

            key, v = line.strip().split(": ")
            val = v.strip()

            if key == "Rule preparer":
                val = "{}_RULE_PREPARER_IDX".format(val.replace(" ", "_").upper())
                ret[key] = idxes["rpidx"][val]
            elif key == "Tokenizer":
                val = "{}_TOKENIZER_IDX".format(val.replace(" ", "_").upper())
                ret[key] = idxes["tnidx"][val]
            elif key == "Token encryptor":
                val = "{}_TOKEN_ENCRYPTOR_IDX".format(val.replace(" ", "_").upper())
                ret[key] = idxes["teidx"][val]
            elif key == "Token detector":
                val = "{}_TOKEN_DETECTOR_IDX".format(val.replace(" ", "_").upper())
                ret[key] = idxes["tdidx"][val]
            elif key == "Tree updater":
                val = "{}_TREE_UPDATER_IDX".format(val.replace(" ", "_").upper())
                ret[key] = idxes["tuidx"][val]
            elif key == "Clustering":
                if val == "True":
                    ret[key] = True
                else:
                    ret[key] = False
            elif key == "Logging":
                if val == "True":
                    ret[key] = True
                else:
                    ret[key] = False
            elif key == "Local test":
                if val == "True":
                    ret[key] = True
                else:
                    ret[key] = False
            elif key == "Hardcode keys":
                if val == "True":
                    ret[key] = True
                else:
                    ret[key] = False
            elif key == "Use tree updater":
                if val == "True":
                    ret[key] = True
                else:
                    ret[key] = False
            else:
                ret[key] = val

    return ret

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bin", required=True, metavar="<binary file>", help="binary file", type=str)
    parser.add_argument("-c", "--conf", required=True, metavar="<configuration file>", help="configuration file", type=str)
    parser.add_argument("-v", "--tuidx", metavar="<tree update index>", help="tree update index", type=str, default="tree_updater/tree_updater.h")
    parser.add_argument("-w", "--rpidx", metavar="<rule preparation index>", help="rule preparation index", type=str, default="rule_preparer/rule_preparer.h")
    parser.add_argument("-x", "--tnidx", metavar="<tokenization index>", help="tokenization index", type=str, default="tokenizer/tokenizer.h")
    parser.add_argument("-y", "--teidx", metavar="<token encryption index>", help="token encryption index", type=str, default="token_encryptor/token_encryptor.h")
    parser.add_argument("-z", "--tdidx", metavar="<token decryption index>", help="token decryption index", type=str, default="token_detector/token_detector.h")
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/ERROR)>", help="log level (DEBUG/INFO/ERROR)", type=str, default="INFO")
    parser.add_argument("-a", "--aes-ni", help="enable/disable AES-NI", action='store_true', default=False)
    parser.add_argument("-t", "--trial", metavar="<# of trials>", help="# of trials", type=int)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)
    binary = args.bin
    cname = args.conf

    if not os.path.exists(binary):
        logging.error("The binary file to be executed does not exist.")
        sys.exit(1)

    if not os.path.exists(cname):
        logging.error("The configuration file does not exist.")
        sys.exit(1)

    if not os.path.exists(args.rpidx):
        logging.error("The index file for the rule preparer does not exist.")
        sys.exit(1)

    if not os.path.exists(args.tnidx):
        logging.error("The index file for the tokenizer does not exist.")
        sys.exit(1)

    if not os.path.exists(args.teidx):
        logging.error("The index file for the token encryptor does not exist.")
        sys.exit(1)

    if not os.path.exists(args.tdidx):
        logging.error("The index file for the token detector does not exist.")
        sys.exit(1)

    if not os.path.exists(args.tuidx):
        logging.error("The index file for the tree updater does not exist.")
        sys.exit(1)

    idxes = {}
    idxes["rpidx"] = parse_index_file(args.rpidx)
    idxes["tnidx"] = parse_index_file(args.tnidx)
    idxes["teidx"] = parse_index_file(args.teidx)
    idxes["tdidx"] = parse_index_file(args.tdidx)
    idxes["tuidx"] = parse_index_file(args.tuidx)

    conf = parse_config(cname, idxes)

    os.environ["LD_LIBRARY_PATH"] = "../lib"
    if not args.aes_ni:
        print ("AES-NI is disabled")
        os.environ["OPENSSL_ia32cap"] = "~0x200000200000000"
    else:
        print ("AES-NI is enabled")

    cmd = ["./{}".format(binary)]

    if args.trial:
        cmd.append("-t")
        cmd.append(str(args.trial))

    if "Rule preparer" in conf:
        cmd.append("-a")
        cmd.append(str(conf["Rule preparer"]))

    if "Tokenizer" in conf:
        cmd.append("-b")
        cmd.append(str(conf["Tokenizer"]))

    if "Token encryptor" in conf:
        cmd.append("-c")
        cmd.append(str(conf["Token encryptor"]))

    if "Token detector" in conf:
        cmd.append("-d")
        cmd.append(str(conf["Token detector"]))

    if "Tree updater" in conf:
        cmd.append("-e")
        cmd.append(str(conf["Tree updater"]))

    if "Name" in conf:
        cmd.append("-n")
        cmd.append(conf["Name"])

    if "Rule filename" in conf:
        cmd.append("-r")
        cmd.append(conf["Rule filename"])

    if "Clustering" in conf:
        if conf["Clustering"]:
            cmd.append("-y")

    if "Num of clusters" in conf:
        cmd.append("-z")
        cmd.append(conf["Num of clusters"])

    if "Num of trees" in conf:
        cmd.append("-u")
        cmd.append(conf["Num of trees"])

    if "Num of entries" in conf:
        cmd.append("-q")
        cmd.append(conf["Num of entries"])

    if "Maximum num of fetched" in conf:
        cmd.append("-g")
        cmd.append(conf["Maximum num of fetched"])

    if "Input filename" in conf:
        cmd.append("-i")
        cmd.append(conf["Input filename"])

    if "Handle filename" in conf:
        cmd.append("-h")
        cmd.append(conf["Handle filename"])

    if "Logging" in conf:
        if conf["Logging"]:
            cmd.append("-l")

    if "Log directory" in conf:
        cmd.append("-o")
        ldir = conf["Log directory"]

        if not os.path.exists(ldir):
            os.makedirs(ldir)

        cmd.append(ldir)

    if "Log prefix" in conf:
        cmd.append("-p")
        cmd.append(conf["Log prefix"])

    if "Log message file" in conf:
        cmd.append("-m")
        cmd.append(conf["Log message file"])

    if "Log flags" in conf:
        cmd.append("-f")
        flags = conf["Log flags"]

        if flags == "cpu":
            num = 1
        elif flags == "time":
            num = 2
        else:
            num = 3
        cmd.append(str(num))
    
    if "Local test" in conf:
        if conf["Local test"]:
            cmd.append("-t")

    if "Hardcode keys" in conf:
        if conf["Hardcode keys"]:
            cmd.append("-k")

    if "Use tree updater" in conf:
        if conf["Use tree updater"]:
            cmd.append("-j")

    if "Window size" in conf:
        cmd.append("-w")
        cmd.append(conf["Window size"])

    if "Token size" in conf:
        cmd.append("-s")
        cmd.append(conf["Token size"])

    logging.debug("cmd: {}".format(' '.join(cmd)))
    output = subprocess.call(cmd)

if __name__ == "__main__":
    main()
