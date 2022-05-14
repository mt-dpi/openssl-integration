import argparse
import logging

GATE_TYPE_AND = 0
GATE_TYPE_XOR = 1
GATE_TYPE_INV = 2

class Gate:
    def __init__(self, idnum, gtype, input1, input2, output):
        self.idnum = idnum
        self.type = gtype
        self.input1 = input1
        self.input2 = input2
        self.output = output

    def get_idnum(self):
        return self.idnum

    def get_type(self):
        return self.type

    def get_input1(self):
        return self.input1

    def get_input2(self):
        return self.input2

    def get_output(self):
        return self.output

    def get_info(self):
        print ("id: {}, type: {}, input1: {}, input2: {}, output: {}".format(self.idnum, self.type, self.input1, self.input2, self.output))

def generate_circuit(rc):
    ret1 = {}
    ret2 = {}
    
    total = 0
    for i in range(len(rc)//4):
        idnum = 4*i
        gtype = int(rc[idnum].strip())
        if gtype == GATE_TYPE_AND:
            total += 1
        input1 = int(rc[idnum+1].strip())
        input2 = int(rc[idnum+2].strip())
        output = int(rc[idnum+3].strip())
        gate = Gate(idnum, gtype, input1, input2, output)
        ret1[idnum] = gate
        ret2[input1] = gate
        if gtype != GATE_TYPE_INV:
            ret2[input2] = gate

    print ("# of AND: {}".format(total))

    return ret1, ret2

def traversal(ilst, gate_by_id, gate_by_output):
    ret = {}
    num = 0
    ret[num] = ilst
    llst = range(29100, 29228)

    total = 0

    while True:
        ilst = ret[num]
        alst = []

        num += 1
        ret[num] = []

        for g in ilst:
            prev = gate_by_id[g]
            if prev.get_output() not in gate_by_output:
                continue
            gate = gate_by_output[prev.get_output()]
            if gate.get_idnum() not in ret[num]:
                ret[num].append(gate.get_idnum())

            if gate.get_type() == GATE_TYPE_AND:
                if gate.get_idnum() not in alst:
                    alst.append(gate.get_idnum())

        total += len(alst)

        if len(ret[num]) == 0:
            print ("layer#: {}".format(num))
            break

    print ("Total: {}".format(total))

    return ret

def preprocessing(fname):
    num_wire = 0
    num_gate = 0
    key_size = 0
    num_input = 0
    blk_size = 128

    with open(fname) as f:
        for line in f:
            if " = " in line:
                k, v = line.strip().split(" = ")
            else:
                continue

            if "num_wire" in k:
                num_wire = int(v.strip()[:-1])

            if "num_gate" in k:
                num_gate = int(v.strip()[:-1])

            if "key_size" in k:
                key_size = int(v.strip()[:-1])

            if "rows" in k:
                raw_circuit = v.strip()[1:-2].split(",")
                gate_by_id, gate_by_output = generate_circuit(raw_circuit)

    num_input = blk_size + key_size

    print ("num_input: {}".format(num_input))
    lst = range(num_input)
    ilst = []

    for inp in lst:
        gate = find_gate_by_input(gate_by_id, inp)
        if gate == None:
            print ("input number: {}".format(inp))
        if gate.get_type() == GATE_TYPE_AND:
            print ("AND gate!: {}".format(gate.get_idnum()))
        if gate.get_idnum() not in ilst:
            ilst.append(gate.get_idnum())

    print ("ilst: {}".format(ilst))
    layers = traversal(ilst, gate_by_id, gate_by_output)
    return layers

def find_gate_by_input(gates, inum):
    ret = None
    for g in gates:
        gate = gates[g]
        
        if gate.get_type() == GATE_TYPE_INV:
            if gate.get_input1() == inum:
                ret = gate
                break
        else:
            if gate.get_input1() == inum or gate.get_input2() == inum:
                ret = gate
                break
    return ret

def write_to_file(ofname, layers):
    with open(ofname, "w") as of:
        for l in layers:
            of.write("{}".format(l))
            for idnum in layers[l]:
                of.write(", {}".format(idnum))

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", metavar="<input file>", help="Input file", type=str, required=True)
    parser.add_argument("-o", "--output", metavar="<output file>", help="Output file", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logLevel = args.log
    logging.basicConfig(level=logLevel)
    
    layers = preprocessing(args.input)
    write_to_file(args.output, layers)

if __name__ == "__main__":
    main()
