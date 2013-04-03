import socketserver
import json
from logging import debug, info, warning

import crypt.rsa
from crypt.rc4 import rc4

from tls import *

def check_enum(enumtype, value, *wants):
    if value not in wants:
        warning('expecting {0} but got {1} instead',
                ' or '.join([enumtype.tostring(w) for w in wants]),
                enumtype.tostring(value))
        return False
    return True

def server_handshake(cert, key):
    handshake_messages = []
    hello = (yield None)
    hello.interpret_body()

    if not check_enum(ContentType, hello.type, ContentType.Handshake) or \
       not check_enum(HandshakeType, hello.body.type, HandshakeType.ClientHello):
        return

    if not check_enum(ProtocolVersion, hello.version,
                      ProtocolVersion.TLSv1_0,
                      ProtocolVersion.TLSv1_1,
                      ProtocolVersion.TLSv1_2):
        return
    
    if not check_enum(ProtocolVersion, hello.body.body.version,
                      ProtocolVersion.TLSv1_0,
                      ProtocolVersion.TLSv1_1,
                      ProtocolVersion.TLSv1_2):
        return
    handshake_messages.append(hello.body)

    version = ProtocolVersion.TLSv1_0
    suite = CipherSuite.TLS_RSA_WITH_RC4_128_SHA
    compression = Compression.Null

    if suite not in hello.body.body.ciphersuites:
        warning('client does not support our selected ciphersuite')
        yield build_fatal_alert(AlertDescription.HandshakeFailure)
        return

    assert compression in hello.body.body.compressions

    server_hello = Message(type = ContentType.Handshake,
                           version = version,
                           body = Handshake(type = HandshakeType.ServerHello,
                                            body = ServerHello(version = version,
                                                               random = Random.generate(),
                                                               session_id = [],
                                                               ciphersuite = suite,
                                                               compression = compression,
                                                               extensions = [])
                                            )
                           )
                                                            
    m = (yield server_hello)
    assert m is None
    handshake_messages.append(server_hello.body)

    certificate = Message(type = ContentType.Handshake,
                          version = version,
                          body = Handshake(type = HandshakeType.Certificate,
                                           body = Certificate(certs = [
                                               ASN1Cert(data = cert)
                                               ])
                                           )
                          )
    m = (yield certificate)
    assert m is None
    handshake_messages.append(certificate.body)
    
    server_hello_done = Message(type = ContentType.Handshake,
                                version = version,
                                body = Handshake(type = HandshakeType.ServerHelloDone,
                                                 body = ServerHelloDone()
                                                 )
                                )
    m = (yield server_hello_done)
    assert m is None
    handshake_messages.append(server_hello_done.body)
    client_kx = (yield None)
    client_kx.interpret_body()

    if not check_enum(ContentType, client_kx.type, ContentType.Handshake) or \
       not check_enum(HandshakeType, client_kx.body.type, HandshakeType.ClientKeyExchange):
        return
    handshake_messages.append(client_kx.body)

    ct = int.from_bytes(client_kx.body.body.body[2:], byteorder = 'big')

    privkey = key['d'], key['n']
    m = crypt.rsa.pkcs1_decrypt(privkey, ct)
    mb = crypt.rsa.int2bytes(m)

    assert mb[0:2] == ProtocolVersion.encode(hello.body.body.version)
    premaster_secret = mb
    
    client_random = hello.body.body.random.encode()
    server_random = server_hello.body.body.random.encode()
    master_secret = TLSv1_0_PRF(48,
                                premaster_secret,
                                "master secret",
                                client_random + server_random)

    key_block_size = 20 + 20 + 16 + 16

    key_block = TLSv1_0_PRF(key_block_size,
                            master_secret,
                            "key expansion",
                            server_random + client_random) # sic

    def split_keys(b, *args):
        i = 0
        o = []
        for n in args:
            o.append(b[i:i+n])
            i += n
        return o

    client_write_mac, server_write_mac, client_write_key, server_write_key = split_keys(key_block, 20, 20, 16, 16)

    rc4_client_write = rc4(client_write_key)
    rc4_server_write = rc4(server_write_key)

    client_change_cipher_spec = (yield None)
    client_change_cipher_spec.interpret_body()
    if not check_enum(ContentType, client_change_cipher_spec.type, ContentType.ChangeCipherSpec):
        return

    recv_num = 0
    send_num = 0

    client_finished = (yield None)
    if not check_enum(ContentType, client_finished.type, ContentType.Handshake):
        return

    def verify(key, seq, m):
        m.body, expect = m.body[:-20], m.body[-20:]

        authd = bytes(Encode.u64(seq)) + bytes(m.header()) + m.body
        
        calc = hmac.new(key, authd, hashlib.sha1).digest()

        if not hmac.compare_digest(calc, expect):
            raise IOError('Bad MAC')
    
    client_finished.body = rc4_client_write.decrypt(client_finished.body)
    verify(client_write_mac, recv_num, client_finished)
    client_finished.interpret_body()
    recv_num += 1

    def hash_handshakes(msgs, h):
        print(h)
        hh = h()
        for m in msgs:
            print(type(m))
            assert isinstance(m, Handshake)
            print(m, bhex(bytes(m)))
            hh.update(bytes(m))
        return hh.digest()

    our_hash = TLSv1_0_PRF(12, master_secret,
                           "client finished",
                           hash_handshakes(handshake_messages, hashlib.md5) +
                           hash_handshakes(handshake_messages, hashlib.sha1))
    assert client_finished.body.body.body == our_hash

    handshake_messages.append(client_finished.body)
    
    return

    change_cipher_spec = Message(type = ContentType.ChangeCipherSpec,
                                 version = version,
                                 body = ChangeCipherSpec())
    yield change_cipher_spec
    
    return

class ssl_handler(socketserver.BaseRequestHandler):
    def load_keys(self):
        with open('keys/key.json', 'r') as f:
            self.key = json.load(f)
        with open('keys/server.der', 'rb') as f:
            self.cert = f.read()
        self.key = dict((k, int(v, 16)) for k, v in self.key.items())
    
    def handle(self):
        self.load_keys()
        
        print('got request from', self.client_address)
        run_protocol(self.request, server_handshake(self.cert, self.key))

        """
        assert m.type == ContentType.Handshake
        print('TLS version:', ProtocolVersion.tostring(m.version))
        assert m.body.type == HandshakeType.ClientHello
        for cs in m.body.body.ciphersuites:
            print(CipherSuite.lookup(cs))
        print('---')
        """

if __name__ == '__main__':
    HOST, PORT = 'localhost', 4433

    server = socketserver.TCPServer((HOST, PORT), ssl_handler)
    server.serve_forever()
