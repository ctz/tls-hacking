import socket
import select
import io
import hashlib
import hmac

from logging import debug

from .protocol_types import *
from .ciphersuites import CipherSuite

def exploratory_clienthello(hostname, suites, version):
    extensions = [
        Extension(ExtensionType.ServerName,
                  ServerNameExtensionBody([ServerName.hostname(hostname)])),
        Extension(ExtensionType.EllipticCurves,
                  EllipticCurvesExtensionBody.all_common_prime_curves()),
        Extension(ExtensionType.ECPointFormats,
                  [1, 0]),
        Extension(ExtensionType.SessionTicket,
                  []),
        Extension(ExtensionType.RenegotiationInfo, [0])
    ]

    if version < ProtocolVersion.TLSv1_0:
        extensions = []
    
    return ClientHello(ciphersuites = suites,
                       compressions = Compression.none(),
                       extensions = extensions,
                       version = version)

def exploratory_handshake(hostname, suites, version):
    return Message(ContentType.Handshake,
                   version,
                   Handshake(HandshakeType.ClientHello,
                             exploratory_clienthello(hostname, suites, version)))

def build_fatal_alert(why):
    return Message(ContentType.Alert,
                   ProtocolVersion.TLSv1_0,
                   Alert(AlertLevel.Fatal, why))

class protocol_handler:
    def __init__(self, co):
        self.co = None

    def process_message(m):
        self.co.send(m)

def wait_for_read(sock):
    r, w, x = select.select([sock], [], [])
    if len(r):
        return
    else:
        raise IOError('timeout')

def bhex(b):
    return ''.join('%02x' % x for x in b)
    
def decompose(bytesin):
    # take messages from the front of bytesin, returning
    # the messages read and the unused remainder of bytesin
    f = io.BytesIO(bytesin)
    o = []

    while True:
        startpos = f.tell()
        if startpos == len(bytesin):
            break
        try:
            m = Message.read(f, opaque = True)
            o.append(m)
        except Exception as e:
            debug(e)
            debug('decomposed-partial %r left %r', o, bytesin[startpos:])
            return o, bytesin[startpos:]
    debug('decomposed-full %r nothing-left', o)
    return o, bytes()

def run_protocol(s, protocol):
    MAX_BUF = 0xffff * 16
    
    buf = bytes()
    msgs = []

    while True:
        for outgoing in protocol.flush():
            if outgoing is None:
                return
            debug('outgoing message is %d bytes', len(bytes(outgoing)))
            s.sendall(bytes(outgoing))

        if msgs:
            incoming = msgs.pop(0)
            protocol.incoming(incoming)
        else:
            wait_for_read(s)
            incoming = s.recv(MAX_BUF)
            if len(incoming) == 0:
                # EOF
                return
            buf += incoming
            recvd, buf = decompose(buf)
            debug('recvd %r', recvd)
            msgs.extend(recvd)

def connect(hostname, port):
    s = socket.create_connection((hostname, port), 5)
    return s

def TLSv1_0_PRF(outlen, secret, label, seed):
    label = bytes(label, 'ASCII')
    secret = bytes(secret)
    seed = bytes(seed)
    ls = len(secret)
    ls1 = ls2 = (ls + 1) // 2

    def xor(xx, yy):
        o = []
        for i in range(len(xx)):
            o.append(xx[i] ^ yy[i])
        return bytes(o)

    def p_hash(hashfn, outlen, k, pt):
        o = []
        a_im = pt
        for i in range(0, outlen, hashfn().digest_size):
            a_i = hmac.new(k, a_im, hashfn).digest()
            output = hmac.new(k, a_i + pt, hashfn).digest()
            o.append(output)
            a_im = a_i
        return bytes(b''.join(o))[:outlen]

    p_md5 = lambda outlen, secret, label: p_hash(hashlib.md5, outlen, secret, label)
    p_sha1 = lambda outlen, secret, label: p_hash(hashlib.sha1, outlen, secret, label)

    return xor(p_md5(outlen, secret[:ls1], label + seed),
               p_sha1(outlen, secret[-ls2:], label + seed))

if __name__ == '__main__':
    v = ContentType.Handshake
    name = ContentType.lookup(v)
    print(v, name, ContentType.tostring(v))

    def pairwise(t, o):
        f = io.BytesIO()
        f.write(bytes(o))
        f.seek(0)
        return t.read(f)

    hs = exploratory_handshake('google.com', CipherSuite.preferred_set(), ProtocolVersion.TLSv1_0)
    newhs = pairwise(Message, hs)
    new2hs = pairwise(Message, newhs)
    print(hs)

    secret = bytes.fromhex('ab' * 48)
    label = "PRF Testvector"
    seed = bytes.fromhex('cd' * 64)
    master_secret = TLSv1_0_PRF(104, secret, label, seed)
    assert len(master_secret) == 104
    assert master_secret == bytes.fromhex('d3d4d1e349b5d515044666d51de32bab258cb521b6b053463e354832fd976754443bcf9a296519bc289abcbc1187e4ebd31e602353776c408aafb74cbc85eff69255f9788faa184cbb957a9819d84a5d7eb006eb459d3ae8de9810454b8b2d8f1afbc655a8c9a013')
