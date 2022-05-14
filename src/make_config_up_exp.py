import argparse
import sys
import os

def make_config(ofname, rname, iname, cnum, pnum, period):
    modules = ["rule_preparer", "tokenizer", "token_encryptor", "token_detector", "tree_updater"]
    num = int(ofname.split("/")[-1].split("_")[0])

    with open(ofname, "w") as of:
        of.write("# Name\n")
        of.write("Name: dpi\n\n")

        of.write("# Rules\n")
        of.write("Rule filename: {}\n".format(rname))
        if num in [2, 5, 7, 9]:
            of.write("Clustering: True\n")
        else:
            of.write("Clustering: False\n")
        of.write("Num of clusters: {}\n\n".format(cnum))

        of.write("# Input data\n")
        of.write("Input filename: {}\n\n".format(iname))

        of.write("# Experiment setting\n")
        of.write("Local test: True\n")
        of.write("Hardcode keys: True\n")
        if num >= 7:
            of.write("Use tree updater: True\n")
        else:
            of.write("Use tree updater: False\n")
        of.write("Num of entries: 16000\n\n".format(pnum))

        of.write("# Search Tree\n")
        if num in [2, 3, 5, 6, 7, 8, 9, 10]:
            of.write("Num of trees: 12\n")
        else:
            of.write("Num of trees: 1\n")
        of.write("Maximum num of fetched: {}\n\n".format(period))

        of.write("# Logging\n")
        of.write("Logging: False\n")
        of.write("Log directory: /home/hwy/dpi-results\n")
        of.write("Log prefix: dpi\n")
        of.write("Log message file: util/dpi_names.h\n")
        of.write("Log flags: util/dpi_flags.h\n")
        of.write("\n")

        of.write("# Parameters\n")
        of.write("Window size: 8\n")
        of.write("Token size: 5\n")
        of.write("\n")

        for m in modules:
            of.write("# Algorithms (")
            lst = [f for f in os.listdir(m) if ".c" in f and f != "{}.c".format(m)]
            for cfile in lst[:-1]:
                f = cfile.split(".")[0]
                of.write("{}/".format(f))
            f = lst[-1].split(".")[0]
            of.write("{})\n".format(f))

            if m == "tokenizer":
                of.write("{}: window_based\n\n".format(m.replace("_", " ").capitalize()))
            else:
                if num == 1:
                    of.write("{}: nonfixedkey_perkeyword\n\n".format(m.replace("_", " ").capitalize()))
                elif num == 2:
                    of.write("{}: nonfixedkey_cluster\n\n".format(m.replace("_", " ").capitalize()))
                elif num == 3:
                    of.write("{}: nonfixedkey_global\n\n".format(m.replace("_", " ").capitalize()))
                elif num == 4:
                    of.write("{}: fixedkey_perkeyword\n\n".format(m.replace("_", " ").capitalize()))
                elif num == 5:
                    of.write("{}: fixedkey_cluster\n\n".format(m.replace("_", " ").capitalize()))
                elif num == 6:
                    of.write("{}: fixedkey_global\n\n".format(m.replace("_", " ").capitalize()))
                elif num == 7:
                    of.write("{}: nonfixedkey_cluster\n\n".format(m.replace("_", " ").capitalize()))
                elif num == 8:
                    of.write("{}: nonfixedkey_global\n\n".format(m.replace("_", " ").capitalize()))
                elif num == 9:
                    of.write("{}: fixedkey_cluster\n\n".format(m.replace("_", " ").capitalize()))
                elif num == 10:
                    of.write("{}: fixedkey_global\n\n".format(m.replace("_", " ").capitalize()))

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", help="configuration filename", type=str, required=True)
    parser.add_argument("-r", "--rule", help="rule filename", type=str, required=True)
    parser.add_argument("-i", "--input", help="input filename", type=str, required=True)
    parser.add_argument("-p", "--pnum", help="previous num of entries", type=int, default=8000)
    parser.add_argument("-q", "--period", help="period", type=int, required=True)
    parser.add_argument("-a", "--rule-preparer", help="rule preparer directory", type=str, default="rule_preparer")
    parser.add_argument("-b", "--tokenizer", help="tokenizer directory", type=str, default="tokenizer")
    parser.add_argument("-c", "--token-encryptor", help="token encryptor directory", type=str, default="token_encryptor")
    parser.add_argument("-d", "--token-detector", help="token detector directory", type=str, default="token_detector")
    parser.add_argument("-n", "--num-of-clusters", help="number of clusters", type=int, default=1)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    ofname = args.output
    rname = args.rule
    iname = args.input
    cnum = args.num_of_clusters
    pnum = args.pnum
    period = args.period

    if not os.path.exists(rname):
        print ("The rule file does not exist.")
        sys.exit(1)

    if not os.path.exists(iname):
        print ("The input file does not exist.")
        sys.exit(1)

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

    make_config(ofname, rname, iname, cnum, pnum, period)

if __name__ == "__main__":
    main()
