import argparse

def keywords(fname, ofname, wsize):

    with open(ofname, "w") as of:
        with open(fname, "r") as f:
            for line in f:
                tmp = line[:-1]
                end = len(tmp) - wsize + 1
                for i in range(end):
                    token = tmp[i:i+wsize]
                    of.write("{}\n".format(token))

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-w', '--wsize', metavar='<window size>',
                        help='window size', required=True, type=int)
    parser.add_argument('-i', '--input', metavar='<input file name>',
                        help='input file name', required=True, type=str)
    parser.add_argument('-o', '--output', metavar='<output file name>',
                        help='output file name', default='output.csv', type=str)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()

    ret = keywords(args.input, args.output, args.wsize)


if __name__ == '__main__':
    main()
