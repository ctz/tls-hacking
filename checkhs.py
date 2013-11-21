from tls.protocol_types import *

import sys
import io

def readhex(ff):
    b = []
    with open(ff, 'r') as f:
        for ll in f:
            bb = [int(y, 16) for y in ll.strip().split()]
            b.extend(bb)
    return bytes(b)

def readbin(ff):
    with open(ff, 'rb') as f:
        return f.read()

def dump(b):
    return ' '.join('{0:02x}'.format(x) for x in b)

def decode_messages(b):
    ll = len(b)
    f = io.BytesIO(b)

    while f.tell() != ll:
        yield Message.read(f)

if __name__ == '__main__':
    for fn in sys.argv[1:]:
        if fn.endswith('.hex'):
            b = readhex(fn)
        else:
            b = readbin(fn)

        for msg in decode_messages(b):
            rb = msg.encode()
            msg2 = Message.decode(bytes(rb))
            print(msg)
            print(msg2)
