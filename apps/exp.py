import argparse
import sys
import os
import math
from subprocess import Popen, PIPE

def average(lst):
    if len(lst) == 0:
        return 0
    return sum(lst)/len(lst)

def stdev(lst):
    squares = []
    for elem in lst:
        squares.append(elem * elem)
    var = average(squares) - average(lst) **2
    return math.sqrt(var)

def run(binary, trial, domain, port, length):
    for _ in range(trial):
        cmd = []
        cmd.append(binary)
        cmd.append("-d")
        cmd.append(domain)
        cmd.
        ps = Popen(


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bin", metavar='<binary>',
                        help='binary', type=str, required=True)
    parser.add_argument("-d", "--domain", metavar='<domain>',
                        help='domain', type=str, required=True)
    parser.add_argument("-p", "--port", metavar='<port>',
                        help='port', type=int, required=True)
    parser.add_argument("-l", "--length", metavar='<length>',
                        help='length', type=int, required=True)
    parser.add_argument("-t", "--trial", metavar='<# of trials>',
                        help='# of trials', type=int, default=100)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    ret = run(args.bin, args.trial, args.domain, args.port, args.length)

if __name__ == '__main__':
    main()
