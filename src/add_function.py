import argparse
import sys
import os
import logging

def generate_table(tname):
    fname = "{}/{}_table.h".format(tname, tname)

    lst = [f for f in os.listdir(tname)
            if f[-2:] == ".c" and f != "{}.c".format(tname)]

    with open(fname, "w") as of:
        of.write("#ifndef __{}_TABLE_H__\n".format(tname.upper()))
        of.write("#define __{}_TABLE_H__\n".format(tname.upper()))
        of.write("\n")
        of.write("#include \"{}.h\"\n".format(tname))
        of.write("\n")

        if tname == "rule_preparer":
            of.write("static int (*rule_preparation_table[{}])(dpi_t *dpi) = {{\n".format(len(lst)+1))
            of.write("\tNULL,\n")
            for f in lst:
                n = f.split(".")[0]
                of.write("\t{}_rule_preparation,\n".format(n))
            of.write("};\n")
        elif tname == "tokenizer":
            of.write("static token_t *(*tokenization_table[{}])(msg_t *msg) = {{\n".format(len(lst)+1))
            of.write("\tNULL,\n")
            for f in lst:
                n = f.split(".")[0]
                of.write("\t{}_get_next_token,\n".format(n))
            of.write("};\n")
        elif tname == "token_encryptor":
            of.write("static etoken_t *(*token_encryption_table[{}])(dpi_t *dpi, token_t *token) = {{\n".format(len(lst)+1))
            of.write("\tNULL,\n")
            for f in lst:
                n = f.split(".")[0]
                of.write("\t{}_token_encryption,\n".format(n))
            of.write("};\n")
        elif tname == "token_detector":
            of.write("static int (*token_detection_table[{}])(dpi_t *dpi, etoken_t *etoken) = {{\n".format(len(lst)+1))
            of.write("\tNULL,\n")
            for f in lst:
                n = f.split(".")[0]
                of.write("\t{}_token_detection,\n".format(n))
            of.write("};\n")
        elif tname == "tree_updater":
            of.write("static int (*tree_update_table[{}])(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue) = {{\n".format(len(lst)+1))
            of.write("\tNULL,\n")
            for f in lst:
                n = f.split(".")[0]
                of.write("\t{}_tree_update,\n".format(n))
            of.write("};\n")

        of.write("#endif /* __{}_TABLE_H__ */\n".format(tname.upper()))

def generate_header(tname):
    fname = "{}/{}.h".format(tname, tname)

    lst = [f for f in os.listdir(tname) 
            if f[-2:] == ".c" and f != "{}.c".format(tname)]

    with open(fname, "w") as of:
        of.write("#ifndef __{}_H__\n".format(tname.upper()))
        of.write("#define __{}_H__\n".format(tname.upper()))
        of.write("\n")
        of.write("#include <dpi/dpi.h>\n")
        of.write("#include <dpi/dpi_types.h>\n")
        of.write("#include <dpi/debug.h>\n")
        of.write("#include \"{}_local.h\"\n".format(tname))
        of.write("\n")

        idx = 0
        of.write("#define NONE_{}_IDX {}\n".format(tname.upper(), idx))
        idx += 1

        for f in lst:
            n = f.split(".")[0]
            of.write("#define {}_{}_IDX {}\n".format(n.upper(), tname.upper(), idx))
            idx += 1
        of.write("\n")
        of.write("{}_t *init_{}(conf_t *conf);\n".format(tname, tname))
        of.write("void free_{}({}_t *module);\n".format(tname, tname))

        for f in lst:
            n = f.split(".")[0]
            if tname == "rule_preparer":
                of.write("int {}_rule_preparation(dpi_t *dpi);\n".format(n))
            elif tname == "tokenizer":
                of.write("token_t *{}_get_next_token(msg_t *msg);\n".format(n))
            elif tname == "token_encryptor":
                of.write("etoken_t *{}_token_encryption(dpi_t *dpi, token_t *token);\n".format(n))
            elif tname == "token_detector":
                of.write("int {}_token_detection(dpi_t *dpi, etoken_t *etoken);\n".format(n))
            elif tname == "tree_updater":
                of.write("int {}_tree_update(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue);\n".format(n))

        of.write("\n")
        of.write("#endif /* __{}_H__ */\n".format(tname.upper()))

def generate_template(tname, name):
    fname = "{}/{}.c".format(tname, name)

    with open(fname, "w") as of:
        if tname == "rule_preparer":
            of.write("#include <dpi/debug.h>\n")
            of.write("#include <dpi/defines.h>\n")
            of.write("#include \"rule_preparer.h\"\n")
            of.write("\n")
            of.write("int {}_rule_preparation(dpi_t *dpi)\n".format(name))
            of.write("{\n")
            of.write("\tfstart(\"dpi: %p\", dpi);\n")
            of.write("\tassert(dpi != NULL);\n")
            of.write("\n")
            of.write("\tint ret;\n")
            of.write("\tret = FAILURE;\n")
            of.write("\n")
            of.write("\tffinish(\"ret: %d\", ret);\n")
            of.write("\treturn ret;\n")
            of.write("}\n")
    
        elif tname == "tokenizer":
            of.write("#include <dpi/debug.h>\n")
            of.write("#include <dpi/defines.h>\n")
            of.write("#include \"tokenizer.h\"\n")
            of.write("\n")
            of.write("token_t *{}_get_next_token(msg_t *msg)\n".format(name))
            of.write("{\n")
            of.write("\tfstart(\"msg: %p\", msg);\n")
            of.write("\tassert(msg != NULL);\n")
            of.write("\n")
            of.write("\ttoken_t *ret;\n")
            of.write("\tret = NULL;\n")
            of.write("\n")
            of.write("\tffinish(\"ret: %p\", ret);\n")
            of.write("\treturn ret;\n")
            of.write("}\n")

        elif tname == "token_encryptor":
            of.write("#include <dpi/debug.h>\n")
            of.write("#include <dpi/defines.h>\n")
            of.write("#include \"token_encryptor.h\"\n")
            of.write("\n")
            of.write("etoken_t *{}_token_encryption(dpi_t *dpi, token_t *token)\n".format(name))
            of.write("{\n")
            of.write("\tfstart(\"dpi: %p, token: %p\", dpi, token);\n")
            of.write("\tassert(dpi != NULL);\n")
            of.write("\n")
            of.write("\tetoken_t *ret;\n")
            of.write("\tret = NULL;\n")
            of.write("\n")
            of.write("\tffinish(\"ret: %p\", ret);\n")
            of.write("\treturn ret;\n")
            of.write("}\n")

        elif tname == "token_detector":
            of.write("#include <dpi/debug.h>\n")
            of.write("#include <dpi/defines.h>\n")
            of.write("#include \"token_detector.h\"\n")
            of.write("\n")
            of.write("int {}_token_detection(dpi_t *dpi, etoken_t *etoken)\n".format(name))
            of.write("{\n")
            of.write("\tfstart(\"dpi: %p, etoken: %p\", dpi, etoken);\n")
            of.write("\tassert(dpi != NULL);\n")
            of.write("\tassert(etoken != NULL);\n")
            of.write("\n")
            of.write("\tint ret;\n")
            of.write("\tret = FALSE;\n")
            of.write("\n")
            of.write("\tffinish(\"ret: %d\", ret);\n")
            of.write("\treturn ret;\n")
            of.write("}\n")

        elif tname == "tree_updater":
            of.write("#include <dpi/debug.h>\n")
            of.write("#include <dpi/defines.h>\n")
            of.write("#include \"tree_updater.h\"\n")
            of.write("\n")
            of.write("int {}_tree_update(dpi_t *dpi, etoken_t *etoken, int idx, int result, int cvalue)\n".format(name))
            of.write("{\n")
            of.write("\tfstart(\"dpi: %p, etoken: %p, idx: %d, result: %d, cvalue: %d\", dpi, etoken, idx, result, cvalue);\n")
            of.write("\tassert(dpi != NULL);\n")
            of.write("\n")
            of.write("\tint ret;\n")
            of.write("\tret = FALSE;\n")
            of.write("\n")
            of.write("\tffinish(\"ret: %d\", ret);\n")
            of.write("\treturn ret;\n")
            of.write("}\n")

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--type", required=True, metavar="<module type>", help="module type", type=str)
    parser.add_argument("-n", "--name", metavar="<new function name>", help="new function name", type=str)
    parser.add_argument("-u", "--update", help="update header and table", action="store_true", default=False)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    tname = args.type
    name = args.name

    if not os.path.exists(tname):
        logging.error("The directory {} does not exist.".format(tname))
        sys.exit(1)

    if not args.update:
        if not name:
            logging.error("New function name should be inserted")
            sys.exit(1)
        fname = "{}/{}.c".format(tname, name)

        if os.path.exists(fname):
            logging.error("The same name of the {} exists. Please insert another name for the {} to be defined".format(tname, tname))
            sys.exit(1)
        generate_template(tname, name)

    generate_header(tname)
    generate_table(tname)

if __name__ == "__main__":
    main()
