# -*- coding: utf-8 -*

import sys

if sys.version > '3':
    PY3 = True
    print("\r\nVersion:" + sys.version)
    from upload_python3 import *
else:
    PY3 = False
    print("\r\nVersion:" + sys.version)
    from upload_python2 import *

def usage():
    print('neuron_firmware_upgrade.py usage:')
    print('-h, --help: Print help message.')
    print('-p, --port: Serial port for upgrade')
    print('-i, --input : The path of the file to be uploaded')
    print('-o, --output: The path of the file in flash')

def main():
    opts, args = getopt.getopt(sys.argv[1:], "hp:i:o:")
    for op, value in opts: 
        if op == "-p":
            serial_name = value 
        elif op == "-i":
            input_file_path = value
        elif op == "-o":
            target_file_path = value
        elif op == "-h":
            usage()
            os._exit(1)
    try:
        main_task(serial_name, input_file_path, target_file_path)
    except SystemExit as ex:
        if str(ex) == '1':
            print('\r\nTransmission failed exit!')
        elif str(ex) == '2':
            print('\r\nExit the firmware update script！')
        else:
            print('\r\nA fatal error occurred!')

if __name__ == '__main__':
    main()