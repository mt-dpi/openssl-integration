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

def parse_config(cname):
    ret = {}

    with open(cname, "r") as f:
        for line in f:
            if line[0] == "#":
                continue

            if line.strip() == "":
                continue

            key, v = line.strip().split(": ")
            val = v.strip()
            ret[key] = val

    return ret

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bin", required=True, metavar="<binary file>", help="binary file", type=str)
    parser.add_argument("-c", "--conf", required=True, metavar="<configuration file>", help="configuration file", type=str)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/ERROR)>", help="log level (DEBUG/INFO/ERROR)", type=str, default="INFO")
    parser.add_argument("-a", "--aes-ni", help="enable/disable AES-NI", action='store_true', default=True)
    args = parser.parse_args()
    return args

def main():
    if os.geteuid() != 0:
        logging.error("You need to have root privileges to run this script\nPlease try again with 'sudo'")
        sys.exit(1)

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

    conf = parse_config(cname)

    os.environ["LD_LIBRARY_PATH"] = "../lib"
    if not args.aes_ni:
        logging.info("AES-NI is disabled")
        os.environ["OPENSSL_ia32cap"] = "~0x200000200000000"
    else:
        logging.info("AES-NI is enabled")

    cmd = ["./{}".format(binary)]

    if "Name" in conf:
        cmd.append("-n")
        cmd.append(conf["Name"])

    if "Rule filename" in conf:
        cmd.append("-r")
        cmd.append(conf["Rule filename"])

    if "Port" in conf:
        cmd.append("-1")
        cmd.append(conf["Port"])

    if "Certificate" in conf:
        cmd.append("-2")
        cmd.append(conf["Certificate"])

    if "Private Key" in conf:
        cmd.append("-3")
        cmd.append(conf["Private Key"])

    if "CA Certificate" in conf:
        cmd.append("-4")
        cmd.append(conf["CA Certificate"])

    logging.debug("cmd: {}".format(' '.join(cmd)))
    output = subprocess.call(cmd)

if __name__ == "__main__":
    main()
