#!/usr/bin/python3

import sys
import base64
import argparse
from pathlib import Path

config = {
    'xorkey' : 0,
    'base64' : False,
    'command' : '',
}

def parseOptions(argv):
    global config
    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <command|file>')

    parser.add_argument('command', nargs='?', help = 'Specifies either a command to encode or script file\'s path')
    parser.add_argument('-b', '--base64', action='store_true', help = 'Consider input as Base64 encoded. If both options, --base64 and --xor are specified, the program will apply them accordingly: Base64Encode(XorEncode(data, XorKey))')
    parser.add_argument('-x', '--xor', dest='xor', metavar = 'KEY', default = '0x00', type=str, help = 'Consider input as Base64 encoded. If both options, --base64 and --xor are specified, the program will apply them accordingly: Base64Encode(XorEncode(data, XorKey))')

    opts = parser.parse_args()

    if len(argv) < 2:
        parser.print_help()
        sys.exit(1)

    try:
        if opts.xor:
            config['xorkey'] = int(opts.xor, 16)
    except:
        print('[-] Incorrect xor key number format. Must be in Hex.')
        sys.exit(1)

    config['base64'] = opts.base64
    config['command'] = opts.command

    if config['xorkey'] and config['xorkey'] != 0 and config['xorkey'] < 0 or config['xorkey'] > 0xff:
        print('[-] XOR key must be in range <0, 0xff>')
        sys.exit(1)

    return (opts)

def getData():
    my_file = Path(config['command'])
    try:
        if my_file.is_file():
            with open(my_file) as f:
                return f.read()
    except:
        pass

    return config['command']

def base64Encode(x):
    return base64.b64encode(x)

def xorEncode(data, key):
    xored = []
    for i, byte in enumerate(data):
        xored.append(byte ^ ord(key))
    return bytearray(xored)

def main(argv):
    (opts) = parseOptions(argv)
    if not opts:
        print('Options parsing failed.')
        return False

    data = getData().encode()
    out = data

    if config['xorkey'] != 0:
        out = xorEncode(out, ""+chr(config['xorkey']))

    if config['base64']:
        out = base64Encode(out)

    sys.stdout.write(out.decode())

if __name__ == '__main__':
    main(sys.argv)