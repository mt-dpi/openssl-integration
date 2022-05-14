import argparse

def remove(fname, ofname):
    d = []

    with open(ofname, "w") as of:
        with open(fname, "r") as f:
            for line in f:
                tmp = line[:-1]
                if tmp not in d:
                    of.write("{}\n".format(tmp))
                    d.append(tmp)

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', metavar='<input file name>',
                        help='input file name', required=True, type=str)
    parser.add_argument('-o', '--output', metavar='<output file name>',
                        help='output file name', default='output.csv', type=str)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    ret = remove(args.input, args.output)

if __name__ == '__main__':
    main()
