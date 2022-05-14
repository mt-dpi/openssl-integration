import argparse
import logging
import os
import time

def collect(tname):
    with open(tname, "r") as f:
        for line in f:
            rank, site = line.strip().split(", ")
            num = len(site.split(".")) - 1
            if not ("www" in site or num > 1):
                site = "www.{}".format(site)

            if not os.path.exists(site):
                os.system("wget --no-parent -r https://{}".format(site))

            time.sleep(5)

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--site", metavar='<top site list>',
                        help='top site list', default=".")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    ret = collect(args.site)

if __name__ == '__main__':
    main()
