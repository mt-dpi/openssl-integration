import argparse
import logging
from matplotlib import pyplot as plt

def create_x(t, w, n, d):
    return [t*x + w*n for x in range(d)]

def draw_graph(fname):
    topics = ["0", "1k", "2k", "4k", "8k", "16k", "32k"]
    data = {}

    with open(fname, "r") as f:
        keys = f.readline().strip().split(", ")
        for line in f:
            tmp = line.strip().split(", ")
            conf = int(tmp[0])
            data[conf] = {}
            cluster = int(tmp[1])
            data[conf][cluster] = {}
            
            for i in range(2, 11):
                data[conf][cluster][keys[i]] = float(tmp[i])

    plt.rcParams["font.family"] = "Times New Roman"
    plt.rcParams["font.size"] = 16
    plt.figure(figsize=(10, 4), dpi=100).tight_layout()

    blindbox = []
    sscdpi = []

    for i in ["0", "1000", "2000", "4000", "8000", "16000", "32000"]:
        blindbox.append(round(data[1][1][i] / 1000, 2))
        sscdpi.append(round(data[4][1][i] / 1000, 2))
        percent = round((round(data[1][1][i] / 1000, 2) - round(data[4][1][i] / 1000, 2)) / round(data[1][1][i] / 1000, 2), 4)
        print ("percent: {}".format(percent * 100))

    blindbox_x = create_x(2, 0.8, 1, 7)
    sscdpi_x = create_x(2, 0.8, 2, 7)

    ax = plt.subplot()
    b = ax.bar(blindbox_x, blindbox, color="white", edgecolor="black")
    s = ax.bar(sscdpi_x, sscdpi, color="black")

    middle_x = [(a+b)/2 for (a,b) in zip(blindbox_x, sscdpi_x)]
    ax.set_xticks(middle_x)
    ax.set_xticklabels(topics)
    plt.legend([b, s], ["BlindBox", "MT-DPI"], loc="lower center", bbox_to_anchor=(0.5, -0.45), ncol=3)
    
#    plt.xticks()
    plt.xlabel("# of Entries in Counter Table")
    plt.ylabel("Sender Overhead in Time (\u03bcs)")
    plt.subplots_adjust(left=0.08, top=0.95, bottom=0.30, right=0.98)
    plt.show()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", metavar="<input file>", help="Input file", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logLevel = args.log
    logging.basicConfig(level=logLevel)
    
    draw_graph(args.input)

if __name__ == "__main__":
    main()
