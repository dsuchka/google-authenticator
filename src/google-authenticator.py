#!/usr/bin/python

import os
import sys
import time
import hmac
import base64
import struct
import hashlib
import optparse
import configparser
import yaml

from typing import Union, Dict, List

def get_hotp_token(secret: str, intervals_no: int) -> int:
    secret = secret.replace(" ", "")
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h

def get_totp_token(secret) -> str:
    value = get_hotp_token(secret, intervals_no=int(time.time())//30)
    return f"{value:06d}"

def main() -> int:
    parser = optparse.OptionParser("Usage: %prog [options] [PATH ELEMENTS]")

    parser.add_option("-c", "--config", metavar="FILE",
        action="store", default="~/.google-authenticator.ini",
        help="path to the configuration file (this is not secrets file!)")

    parser.add_option("-s", "--secrets-file",
        action="store", default=None, metavar="FILE",
        help="path to the secrets file (overrides configuration value)")

    parser.add_option("-S", "--secret", metavar="BASE32",
        action="store", default=None,
        help="use the specified secret unstead of reading secrets file")

    (options, args) = parser.parse_args()

    def view_path(path: List[str]):
        return "⇒".join(path)

    # Use specified secret if given
    if (options.secret is not None):
        if (not args):
            args = ['(given secret)']
        print(f"{view_path(args)}: {get_totp_token(options.secret)}")
        return 0

    # Read configuration file
    config = configparser.ConfigParser()
    config.read(os.path.expanduser(options.config))

    # Read secrets file (YAML format)
    secrets_file = options.secrets_file
    if (secrets_file is None):
        try:
            secrets_file = config['CORE']['secrets-file']
        except KeyError:
            print(f"Configuration error: no found `secrets-file' in section [CORE]", file=sys.stderr)
            return 1
    try:
        with open(os.path.expanduser(secrets_file)) as f:
            data = yaml.safe_load(f)
    except Exception as e:
        print(f"Could not load secrets file `{secrets_file}': {e}", file=sys.stderr)
        return 2

    path = []
    while (args):
        if isinstance(data, list) and (len(args) <= 1):
            break
        path.append(args[0])
        if (args[0] not in data):
            print(f"Could not found path element #{len(path)}:"
                f" `{args[0]}` (path: {view_path(path)})", file=sys.stderr)
            return 3
        data = data[args[0]]
        args = args[1:]

    name = None if (not args) else args[0]

    def show_deep(root: Union[Dict, List], name: str, path: List[str]) -> int:
        if (not isinstance(root, list)):
            count = 0
            for k in root.keys():
                count += show_deep(root[k], name, path + [k])
            return count
        if (name is not None):
            root = list(filter(
                lambda x: isinstance(x, dict) and (x.get('name', None) == name),
                root))
        count = 0
        for x in root:
            if (not isinstance(x, dict)) or ('name' not in x) or ('code' not in x):
                continue
            n = x['name']
            c = x['code']
            p = path + [n]
            print(f"{view_path(p)}: {get_totp_token(c)}")
            count += 1
        return count

    count = show_deep(data, name, path)
    if (not count):
        print(f"Could not find specified path in the secrets file", file=sys.stderr)
        return 255

    return 0

if __name__ == "__main__":
    sys.exit(main())
