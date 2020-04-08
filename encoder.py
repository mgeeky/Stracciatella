#!/usr/bin/python3

import sys
import base64
import argparse
from pathlib import Path

config = {
    'xorkey' : 0,
    'command' : '',
}

def parseOptions(argv):
    global config
    parser = argparse.ArgumentParser(prog = argv[0], usage='%(prog)s [options] <command|file>')

    parser.add_argument('command', nargs='?', help = 'Specifies either a command or script file\'s path for encoding')
    parser.add_argument('-x', '--xor', dest='xor', metavar = 'KEY', default = '0x00', type=str, help = 'Specifies command/file XOR encode key (one byte)')
    parser.add_argument('-o', '--output', dest='output', metavar = 'PATH', type=str, help = '(optional) Output file. If not given - will echo output to stdout')

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

    config['command'] = opts.command

    if config['xorkey'] and config['xorkey'] != 0 and config['xorkey'] < 0 or config['xorkey'] > 0xff:
        print('[-] XOR key must be in range <0, 0xff>')
        sys.exit(1)

    return (opts)

def getData():
    my_file = Path(config['command'])
    try:
        if my_file.is_file():
            with open(my_file, 'rb') as f:
                return f.read()
    except:
        pass

    return config['command']

def base64Encode(x):
    return base64.b64encode(x)

def xorEncode(data, key):
    xored = []
    for byte in data:
        xored.append(byte ^ ord(key))
    return bytearray(xored)[:len(data)]

def main(argv):
    (opts) = parseOptions(argv)
    if not opts:
        print('Options parsing failed.')
        return False

    data = getData()
    out = data

    if config['xorkey'] != 0:
        out = base64Encode(xorEncode(out, ""+chr(config['xorkey'])))

    if (opts.output):
        with open(opts.output, 'wb') as f:
            f.write(out)

        print('[+] Written {} bytes to: {}'.format(len(out), opts.output))
    else:
        sys.stdout.write(out.decode())

if __name__ == '__main__':
    main(sys.argv)