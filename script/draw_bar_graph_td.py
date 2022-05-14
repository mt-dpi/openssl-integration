import argparse
import logging
from matplotlib import pyplot as plt

def create_x(t, w, n, d):
    return [t*x + w*n for x in range(d)]

def draw_graph(fname):
    topics = ["1k", "2k", "4k", "8k", "16k", "32k"]
    data = {}

    with open(fname, "r") as f:
        matched = "matched"
        klst = f.readline().strip().split(", ")
        keys = []
        data[matched] = {}
        for k in klst:
            if "k" in k:
                keys.append(k.split(" ")[0])
            else:
                keys.append(k)

        for line in f:
            if line.strip() == "":
                matched = "unmatched"
                data[matched] = {}
                f.readline()
                continue

            tmp = line.strip().split(", ")
            conf = int(tmp[0])
            data[matched][conf] = {}
            cluster = int(tmp[1])
            data[matched][conf][cluster] = {}
            
            for i in range(2, 8):
                data[matched][conf][cluster][keys[i]] = float(tmp[i])

    plt.rcParams["font.family"] = "Times New Roman"
    plt.rcParams["font.size"] = 16
    plt.figure(figsize=(10, 4), dpi=100).tight_layout()

    blindbox_matched = []
    blindbox_unmatched = []
    sscdpi_matched = []
    sscdpi_unmatched = []

    for i in topics:
        blindbox_matched.append(round(data["matched"][1][1][i] / 1000, 4))
        blindbox_unmatched.append(round(data["unmatched"][1][1][i] / 1000, 4))
        sscdpi_matched.append(round(data["matched"][4][1][i] / 1000, 4))
        sscdpi_unmatched.append(round(data["unmatched"][4][1][i] / 1000, 4))

    blindbox_matched_x = create_x(4, 0.8, 1, 6)
    sscdpi_matched_x = create_x(4, 0.8, 2, 6)
    blindbox_unmatched_x = create_x(4, 0.8, 3, 6)
    sscdpi_unmatched_x = create_x(4, 0.8, 4, 6)

    ax = plt.subplot()
    bm = ax.bar(blindbox_matched_x, blindbox_matched, color="black")
    sm = ax.bar(sscdpi_matched_x, sscdpi_matched, color="white", hatch="///", edgecolor="black")
    bu = ax.bar(blindbox_unmatched_x, blindbox_unmatched, color="white", edgecolor="black")
    su = ax.bar(sscdpi_unmatched_x, sscdpi_unmatched, color="white", hatch="\\\\\\", edgecolor="black")

    middle_x = [(a+b+c+d)/4 for (a,b,c,d) in zip(blindbox_matched_x, sscdpi_matched_x, blindbox_unmatched_x, sscdpi_unmatched_x)]
    ax.set_xticks(middle_x)
    ax.set_xticklabels(topics)
    plt.legend([bm, sm, bu, su], ["BlindBox (O)", "MT-DPI (O)", "BlindBox (X)", "MT-DPI (X)"], loc="lower center", bbox_to_anchor=(0.5, -0.45), ncol=4)
    
#    plt.xticks()
    plt.xlabel("# of Keywords")
    plt.ylabel("Middlebox Overhead in Time (\u03bcs)")
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
