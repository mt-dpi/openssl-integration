import argparse
import sys
import os

def make_config(ofname):
    modules = ["rule_preparer", "tokenizer", "token_encryptor", "token_detector", "tree_updater"]

    with open(ofname, "w") as of:
        of.write("# Name\n")
        of.write("Name: dpi\n\n")

        of.write("# Rules\n")
        of.write("Rule filename: ../data/rules/rule_8bytes_1000.txt\n")
        of.write("Clustering: False\n")
        of.write("Num of clusters: 1\n\n")

        of.write("# Input data\n")
        of.write("Input filename: ../data/inputs/input_1.html\n\n")

        of.write("# Handle data\n")
        of.write("Handle filename: None\n\n")

        of.write("# Experiment setting\n")
        of.write("Local test: True\n")
        of.write("Hardcode keys: True\n")
        of.write("Use tree updater: True\n")
        of.write("Num of entries: 0\n\n")

        of.write("# Search Tree\n")
        of.write("Num of trees: 10\n")
        of.write("Maximum num of fetched: 1000\n\n")

        of.write("# Logging\n")
        of.write("Logging: True\n")
        of.write("Log directory: /home/hyun/dpi-results\n")
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
            of.write("{}: {}\n\n".format(m.replace("_", " ").capitalize(), f))

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", help="configuration filename", type=str, default="dpi.conf")
    parser.add_argument("-a", "--rule-preparer", help="rule preparer directory", type=str, default="rule_preparer")
    parser.add_argument("-b", "--tokenizer", help="tokenizer directory", type=str, default="tokenizer")
    parser.add_argument("-c", "--token-encryptor", help="token encryptor directory", type=str, default="token_encryptor")
    parser.add_argument("-d", "--token-detector", help="token detector directory", type=str, default="token_detector")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    ofname = args.output

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

    make_config(ofname)

if __name__ == "__main__":
    main()
