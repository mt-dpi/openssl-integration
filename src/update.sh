#/bin/bash

python3 add_function.py --type rule_preparer --update
python3 add_function.py --type tokenizer --update
python3 add_function.py --type token_encryptor --update
python3 add_function.py --type token_detector --update
python3 add_function.py --type tree_updater --update

rm ../lib/libdpi.a
make clean
make all

if [[ $# -gt 0 ]] ; then
  python3 make_config.py --output $1
else
  python3 make_config.py
fi
