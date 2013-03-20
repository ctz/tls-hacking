import socket
import select
import io

from protocol_types import *
from ciphersuites import CipherSuite

def exploratory_clienthello(hostname, suites):
    extensions = [
        Extension(ExtensionType.ServerName,
                  ServerNameExtensionBody([ServerName.hostname(hostname)])),
        Extension(ExtensionType.EllipticCurves,
                  EllipticCurvesExtensionBody.all_named_curves()),
        Extension(ExtensionType.RenegotiationInfo, [0])
    ]
    return ClientHello(ciphersuites = suites,
                       compressions = Compression.all(),
                       extensions = extensions)

def exploratory_handshake(hostname, suites):
    return Message(ContentType.Handshake,
                   ProtocolVersion.TLSv1_0,
                   Handshake(HandshakeType.ClientHello,
                             exploratory_clienthello(hostname, suites)))

def build_fatal_alert(why):
    return Message(ContentType.Alert,
                   ProtocolVersion.TLSv1_0,
                   Alert(AlertLevel.Fatal, why))

class protocol_handler:
    def __init__(self, co):
        self.co = None

    def process_message(m):
        self.co.send(m)

def client_handshake(hello):
    print('client_handshake send:', hello)
    m = (yield hello)
    assert m is None

    m = (yield None)
    print('client_handshake recv:', m)
    print('client_handshake fin.')

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

def test(hostname, port):
    with socket.create_connection((hostname, port), 10) as s:
        f = s.makefile(mode = 'rwb')
        f.socket = s # stash for win32 :(
        hello = exploratory_handshake(hostname, CipherSuite.chrome_default_set())
        protocol = client_handshake(hello)
        run_protocol(f, protocol)

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
