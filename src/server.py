import socketserver
from tls import Message, build_fatal_alert, AlertDescription
from tls import ContentType, HandshakeType, CipherSuite, ProtocolVersion

class ssl_handler(socketserver.StreamRequestHandler):
    def handle(self):
        print('got request from', self.client_address)
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

if __name__ == '__main__':
    HOST, PORT = 'localhost', 4433

    server = socketserver.TCPServer((HOST, PORT), ssl_handler)
    server.serve_forever()
