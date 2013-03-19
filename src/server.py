import socketserver
from tls import Message, build_fatal_alert, AlertDescription
from tls import ContentType, HandshakeType, CipherSuite

class ssl_handler(socketserver.StreamRequestHandler):
    def handle(self):
        print('got request from', self.client_address)
        m = Message.read(self.rfile)
        self.wfile.write(bytes(build_fatal_alert(AlertDescription.HandshakeFailure)))
        self.rfile.close()
        self.wfile.close()

        assert m.type == ContentType.Handshake
        assert m.body.type == HandshakeType.ClientHello
        for cs in m.body.body.ciphersuites:
            print(CipherSuite.lookup(cs))
        print('---')

if __name__ == '__main__':
    HOST, PORT = 'localhost', 443

    server = socketserver.TCPServer((HOST, PORT), ssl_handler)
    server.serve_forever()
