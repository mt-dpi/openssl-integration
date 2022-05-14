import subprocess
import argparse
import os

def run(ofdir, ldir, cnum, pnum):

    lst = ["1k", "2k", "4k", "8k", "16k", "32k"]

    for s in [1, 3, 4, 6]:
        for i in lst:
            cmd = []
            cmd.append("python3")
            cmd.append("make_config_tu_exp.py")
            cmd.append("-o")
            cmd.append("{}/{}_1_{}.conf".format(ofdir, s, i))
            cmd.append("-r")
            cmd.append("../data/rules/rule_8bytes_{}.txt".format(i))
            cmd.append("-p")
            cmd.append("{}".format(pnum))
            cmd.append("-l")
            cmd.append("{}".format(ldir))
            subprocess.call(cmd)

    for s in [2, 5]:
        for c in [2, 4, 6]:
            for i in lst:
                cmd = []
                cmd.append("python3")
                cmd.append("make_config_tu_exp.py")
                cmd.append("-o")
                cmd.append("{}/{}_{}_{}.conf".format(ofdir, s, c, i))
                cmd.append("-n")
                cmd.append("{}".format(c))
                cmd.append("-p")
                cmd.append("{}".format(pnum))
                cmd.append("-r")
                cmd.append("../data/rules/rule_8bytes_{}.txt".format(i))
                cmd.append("-l")
                cmd.append("{}".format(ldir))
                subprocess.call(cmd)

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", help="configuration directory", type=str, required=True)
    parser.add_argument("-p", "--pnum", help="previous num of entries", type=int, default=8000)
    parser.add_argument("-l", "--log-directory", help="log directory", type=str, required=True)
    parser.add_argument("-a", "--rule-preparer", help="rule preparer directory", type=str, default="rule_preparer")
    parser.add_argument("-b", "--tokenizer", help="tokenizer directory", type=str, default="tokenizer")
    parser.add_argument("-c", "--token-encryptor", help="token encryptor directory", type=str, default="token_encryptor")
    parser.add_argument("-d", "--token-detector", help="token detector directory", type=str, default="token_detector")
    parser.add_argument("-n", "--num-of-clusters", help="number of clusters", type=int, default=1)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    ofdir = args.output
    cnum = args.num_of_clusters
    pnum = args.pnum
    ldir = args.log_directory

    if not os.path.exists(args.log_directory):
        os.mkdir(args.log_directory)

    if not os.path.exists(args.rule_preparer):
        print ("The directory of the rule preparer does not exist.")
        sys.exit(1)

    if not os.path.exists(args.tokenizer):
        print ("The directory of the tokenizer does not exist.")
        sys.exit(1)

    if not os.path.exists(args.token_encryptor):
        print ("The directory of the token encryptor does not exist.")
        sys.exit(1)

    if not os.path.exists(args.token_detector):
        print ("The directory of the token detector does not exist.")
        sys.exit(1)

    run(ofdir, ldir, cnum, pnum)

if __name__ == "__main__":
    main()
