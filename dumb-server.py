"""
Server which merely reads a ClientHello, and replies with a
ServerHello plus Certificate.  The certificate is read from
a file.
"""

import sys
import socketserver
import socket
import tls.protocol_types as TLS

assert len(sys.argv) == 2, 'usage: script.py <cert.der>'
cert = open(sys.argv[-1], 'rb').read()
version = TLS.ProtocolVersion.TLSv1_0
HOST, PORT = '', 4433

def trivial_server_hello(client_hello):
    compression = TLS.Compression.Null
    extensions = []
    ciphersuite = TLS.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA

    assert ciphersuite in client_hello.body.body.ciphersuites

    m = TLS.Message(type = TLS.ContentType.Handshake,
                    version = version,
                    body = TLS.Handshake(type = TLS.HandshakeType.ServerHello,
                                         body = TLS.ServerHello(version = version,
                                                                random = TLS.Random.generate(),
                                                                session_id = [],
                                                                ciphersuite = ciphersuite,
                                                                compression = compression,
                                                                extensions = extensions)
                                                )
                               )
    return m

def broken_server_cert():
    return TLS.Message(type = TLS.ContentType.Handshake,
                       version = version,
                       body = TLS.Handshake(type = TLS.HandshakeType.Certificate,
                                            body = TLS.Certificate(certs = [TLS.ASN1Cert(data = cert)])
                                            )
                       )

class handler(socketserver.StreamRequestHandler):
    def handle(self):
        m = TLS.Message.read(self.rfile)
        assert m.type == TLS.ContentType.Handshake
        assert m.body.type == TLS.HandshakeType.ClientHello

        # send a server hello, contents don't matter
        server_hello = trivial_server_hello(m)
        self.wfile.write(bytes(server_hello))

        cert = broken_server_cert()
        self.wfile.write(bytes(cert))
        self.rfile.read()

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    address_family = socket.AF_INET6

if __name__ == '__main__':
    server = ThreadedTCPServer((HOST, PORT), handler)
    print('listening on', HOST, PORT)
    server.serve_forever()
