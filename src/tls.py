import socket
import select
import io

from protocol_types import *
from ciphersuites import CipherSuite

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

def wait_for_read(f):
    r, w, x = select.select([f.socket], [], [], 1)
    if len(r):
        return
    else:
        raise IOError('timeout')

def run_protocol(f, protocol):
    recvd = None
    while True:
        try:
            to_send = protocol.send(recvd)
        except StopIteration:
            break
        recvd = None
        if to_send is not None:
            f.write(bytes(to_send))
            f.flush()
        else:
            wait_for_read(f)
            recvd = Message.read(f)

def connect(hostname, port):
    s = socket.create_connection((hostname, port), 5)
    f = s.makefile(mode = 'rwb')
    f.socket = s
    return f

if __name__ == '__main__':
    v = ContentType.Handshake
    name = ContentType.lookup(v)
    print(v, name, ContentType.tostring(v))

    def pairwise(t, o):
        f = io.BytesIO()
        f.write(bytes(o))
        f.seek(0)
        return t.read(f)

    hs = exploratory_handshake('google.com', CipherSuite.preferred_set())
    newhs = pairwise(Message, hs)
    new2hs = pairwise(Message, newhs)
    print(hs)

    assert bytes(hs) == bytes(newhs)
    assert bytes(newhs) == bytes(new2hs)
    #test('www.amazon.com', 443)
    test('www.google.com', 443)
    #test('www.play.com', 443)
    #test('www.twitter.com', 443)
    #test('www.github.com', 443)
