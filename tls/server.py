import socketserver
import json
import copy
from logging import debug, info, warning, error

from .crypt import rsa
from .crypt.rc4 import rc4
from .crypt.aes import encryptData, decryptData

from .tls import *

def check_enum(enumtype, value, *wants):
    if value not in wants:
        warning('expecting %r but got %r instead',
                'or '.join([enumtype.tostring(w) for w in wants]),
                enumtype.tostring(value))
        return False
    return True

def split_keys(b, *args):
    i = 0
    o = []
    for n in args:
        o.append(b[i:i+n])
        i += n
    return o

def bhex(v):
    return ''.join('%02x' % x for x in bytes(v))

def hash_handshakes(msgs, h):
    hh = h()
    for m in msgs:
        assert isinstance(m, Handshake)
        hh.update(bytes(m))
    return hh.digest()

class TLS_RSA_WITH_RC4_128_SHA:
    Suite = CipherSuite.TLS_RSA_WITH_RC4_128_SHA

    def process_client_kx(self, client_kx, server_key):
        ct = int.from_bytes(client_kx.body.body.body[2:], byteorder = 'big')

        privkey = server_key['d'], server_key['n']
        m = rsa.pkcs1_decrypt(privkey, ct)
        self.premaster_secret = rsa.int2bytes(m)
   
    def process_premaster_secret(self, hello, server_hello):
        assert self.premaster_secret[0:2] == ProtocolVersion.encode(hello.body.body.version)
        
        client_random = hello.body.body.random.encode()
        server_random = server_hello.body.body.random.encode()
        self.master_secret = TLSv1_0_PRF(48,
                                         self.premaster_secret,
                                         "master secret",
                                         client_random + server_random)

        def key_expansion(*lengths):
            key_block = TLSv1_0_PRF(sum(lengths),
                                    self.master_secret,
                                    "key expansion",
                                    server_random + client_random) # sic
            return split_keys(key_block, *lengths)

        self.rekey(key_expansion)

        self.send_num = 0
        self.recv_num = 0

    def rekey(self, expand_keys_fn):
        self.client_write_mac, self.server_write_mac, \
                self.client_write_key, self.server_write_key = expand_keys_fn(20, 20, 16, 16)

        self.rc4_client_write = rc4(self.client_write_key)
        self.rc4_server_write = rc4(self.server_write_key)

    def process_client_finished(self, finished, handshake_messages):
        our_hash = TLSv1_0_PRF(12, self.master_secret,
                               "client finished",
                               hash_handshakes(handshake_messages, hashlib.md5) +
                               hash_handshakes(handshake_messages, hashlib.sha1))
        assert finished.body.body.body == our_hash

    def produce_server_finished(self, version, handshake_messages):
        our_hash = TLSv1_0_PRF(12, self.master_secret,
                               "server finished",
                               hash_handshakes(handshake_messages, hashlib.md5) +
                               hash_handshakes(handshake_messages, hashlib.sha1))
        
        server_finished = Message(type = ContentType.Handshake,
                                  version = version,
                                  body = Handshake(type = HandshakeType.Finished,
                                                   body = Finished(body = our_hash)
                                                   )
                                  )
        self.encrypt(server_finished)
        return server_finished

    def _verify(self, msg):
        msg.body, expect = msg.body[:-20], msg.body[-20:]

        authd = bytes(Encode.u64(self.recv_num)) + bytes(msg.header()) + msg.body
        
        calc = hmac.new(self.client_write_mac, authd, hashlib.sha1).digest()

        if calc != expect:
            raise IOError('Bad MAC')
    
    def decrypt(self, msg):
        msg.body = self.rc4_client_write.decrypt(msg.body)
        self._verify(msg)
        self.recv_num += 1
    
    def _sign(self, msg):
        body = bytes(msg.body)
        authd = bytes(Encode.u64(self.send_num)) + bytes(msg.header()) + body
        sig = hmac.new(self.server_write_mac, authd, hashlib.sha1).digest()
        msg.body = body + sig
    
    def encrypt(self, msg):
        self._sign(msg)
        msg.body = self.rc4_server_write.encrypt(msg.body)
        self.send_num += 1

class aes:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def decrypt(self, data):
        rc = decryptData(self.key, self.iv + data, unpad = False)
        self.iv = data[-16:]
        pad_length = rc[-1]
        rc = rc[:-pad_length-1]
        return rc

    def encrypt(self, data):
        npad = 16 - (len(data) % 16)
        padc = npad - 1

        data = data + bytes([padc] * (npad))
        assert len(data) % 16 == 0
        rc = encryptData(self.key, data, iv = self.iv, pad = False)
        self.iv = rc[-16:]
        rc = rc[16:]
        return rc

class TLS_RSA_WITH_AES_256_CBC_SHA(TLS_RSA_WITH_RC4_128_SHA):
    Suite = CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA

    def decrypt(self, msg):
        msg.body = self.aes_client_write.decrypt(msg.body)
        self._verify(msg)
        self.recv_num += 1

    def encrypt(self, msg):
        self._sign(msg)
        msg.body = self.aes_server_write.encrypt(msg.body)
        self.send_num += 1
    
    def rekey(self, expand_keys_fn):
        self.client_write_mac, self.server_write_mac, \
                self.client_write_key, self.server_write_key, \
                self.client_write_iv, self.server_write_iv = expand_keys_fn(20, 20, 32, 32, 16, 16)

        self.aes_client_write = aes(self.client_write_key, self.client_write_iv)
        self.aes_server_write = aes(self.server_write_key, self.server_write_iv)

def choose_ciphersuite(offered):
    if TLS_RSA_WITH_RC4_128_SHA.Suite in offered:
        return TLS_RSA_WITH_RC4_128_SHA()
    if TLS_RSA_WITH_AES_256_CBC_SHA.Suite in offered:
        return TLS_RSA_WITH_AES_256_CBC_SHA()
    else:
        warning('client does not offer our supported suites (%r offered; %r, %r supported)',
            ', '.join(CipherSuite.tostring(w) for w in hello.body.body.ciphersuites),
            CipherSuite.tostring(TLS_RSA_WITH_RC4_128_SHA.Suite),
            CipherSuite.tostring(TLS_RSA_WITH_AES_256_CBC_SHA.Suite)
            )
        raise IOError('no common ciphersuites')

class server_handshake:
    def __init__(self, certs, key, plaintext):
        self.certs = certs
        self.key = key
        self.plaintext = plaintext

        # handshake process is a generator, None indicates the handshake is finished
        self.handshake = self.server_handshake()
        self.handshake.send(None) # start generator

        # filled in by completed handshake
        self.suite = None
        self.version = None
        self.has_heartbeat = False

        # after handshake, this is a buffer of outgoing tls messages
        self.outgoing = []

        try:
            self.plaintext.have_tls(self)
        except:
            pass

    def process_handshake(self, msg):
        try:
            self.handshake.send(msg)
        except StopIteration:
            self.handshake = None

    def incoming(self, msg):
        if self.handshake:
            self.process_handshake(msg)
        else:
            self.read_plaintext(msg)

    def send(self, msg):
        self.outgoing.append(msg)

    def close(self):
        self.send(None)

    def flush(self):
        self.flush_plaintext()

        out = self.outgoing
        self.outgoing = []
        return out
    
    def server_handshake(self):
        info('Server handshake starts')
        handshake_messages = []
        hello = (yield None)
        assert hello is not None, 'EOF when waiting for clienthello'
        info('Server got hello')
        hello.interpret_body()
        debug(hello.to_json())
        debug(hello.body.body.extensions)

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

        self.version = ProtocolVersion.TLSv1_0
        compression = Compression.Null
        extensions = []

        self.has_heartbeat = len([ext for ext in hello.body.body.extensions if ext.type == ExtensionType.Heartbeat and ext.data[0] == 1]) > 0
        debug('heartbeat? ' + str(self.has_heartbeat))
        if self.has_heartbeat:
            extensions.append(Extension(type = ExtensionType.Heartbeat, data = bytes([1])))
            debug('setting heartbeat extension %s' % extensions[-1])

        self.suite = choose_ciphersuite(hello.body.body.ciphersuites)
        debug('using ciphersuite %s', CipherSuite.tostring(self.suite.Suite))
        assert compression in hello.body.body.compressions

        server_hello = Message(type = ContentType.Handshake,
                               version = self.version,
                               body = Handshake(type = HandshakeType.ServerHello,
                                                body = ServerHello(version = self.version,
                                                                   random = Random.generate(),
                                                                   session_id = [],
                                                                   ciphersuite = self.suite.Suite,
                                                                   compression = compression,
                                                                   extensions = extensions)
                                                )
                               )
        self.send(server_hello)
        debug('Server hello sent')
        handshake_messages.append(server_hello.body)

        certificate = Message(type = ContentType.Handshake,
                              version = self.version,
                              body = Handshake(type = HandshakeType.Certificate,
                                               body = Certificate(certs = [
                                                   ASN1Cert(data = cd) for cd in self.certs
                                                   ])
                                               )
                              )
        self.send(certificate)
        debug('Server certificate sent')
        handshake_messages.append(certificate.body)
        
        server_hello_done = Message(type = ContentType.Handshake,
                                    version = self.version,
                                    body = Handshake(type = HandshakeType.ServerHelloDone,
                                                     body = ServerHelloDone()
                                                     )
                                    )
        
        self.send(server_hello_done)
        debug('Server hello-done sent')
        handshake_messages.append(server_hello_done.body)
        client_kx = (yield None)
        debug('Server got client KX msg')
        client_kx.interpret_body()

        if not check_enum(ContentType, client_kx.type, ContentType.Handshake) or \
           not check_enum(HandshakeType, client_kx.body.type, HandshakeType.ClientKeyExchange):
            return
        handshake_messages.append(client_kx.body)

        self.suite.process_client_kx(client_kx, self.key)
        self.suite.process_premaster_secret(hello, server_hello)

        client_change_cipher_spec = (yield None)
        client_change_cipher_spec.interpret_body()
        if not check_enum(ContentType, client_change_cipher_spec.type, ContentType.ChangeCipherSpec):
            return

        client_finished = (yield None)
        debug('Server got client-finished msg')
        if not check_enum(ContentType, client_finished.type, ContentType.Handshake):
            return

        self.suite.decrypt(client_finished)
        client_finished.interpret_body()

        self.suite.process_client_finished(client_finished, handshake_messages)
        handshake_messages.append(client_finished.body)
        
        change_cipher_spec = Message(type = ContentType.ChangeCipherSpec,
                                     version = self.version,
                                     body = ChangeCipherSpec())
        server_finished = self.suite.produce_server_finished(self.version, handshake_messages)

        debug('Server sends change-cipherspec, server-finished msgs')
        self.send(change_cipher_spec)
        self.send(server_finished)
        info('Server handshake completed')

    def read_plaintext(self, request):
        if request.type == ContentType.Heartbeat:
            debug('we got a heartbeat from client')
            self.suite.decrypt(request)

            # offer to plaintext layer
            try:
                self.plaintext.incoming_heartbeat(request)
                return
            except Exception as e:
                import sys
                sys.excepthook(*sys.exc_info())
                pass

            # send response ourselves if plaintext layer doesn't
            request.interpret_body()
            if request.body.type == HeartbeatMessageType.Request:
                self.write_heartbeat_response(request)
            return

        if not check_enum(ContentType, request.type, ContentType.ApplicationData):
            error('unexpected tls message in application data stream; possible client invoked renegotation or shutdown (nyi)')
            self.close()
            return

        self.suite.decrypt(request)
        info('incoming message %r', request)
        self.plaintext.incoming(request.body)

    def flush_plaintext(self):
        for m in self.plaintext.flush():
            self.write_plaintext(m)

    def write_heartbeat_response(self, req):
        if not self.has_heartbeat:
            debug('not sending heartbeat response (not negotiated)')
            return

        debug('sending heartbeat response')
        msg = Message(type = ContentType.Heartbeat,
                      version = self.version,
                      body = Heartbeat(type = HeartbeatMessageType.Response,
                                       payload = req.body.payload))
        self.suite.encrypt(msg)
        self.send(msg)

    def write_heartbeat_request(self, heartbleed_attack = False):
        if not self.has_heartbeat:
            debug('not sending heartbeat request (not negotiated)')
            return

        if heartbleed_attack:
            body = bytes([0x01, # request
                          0x3f, 0xff, # len
                          0x00])
        else:
            body = Heartbeat(type = HeartbeatMessageType.Request,
                             payload = bytes([0]))

        msg = Message(type = ContentType.Heartbeat,
                      version = self.version,
                      body = body)
        self.suite.encrypt(msg)
        self.send(msg)

    def write_plaintext(self, msg):
        info('outgoing message %r', msg)
        if msg is None:
            debug('plaintext source said EOF')
            self.send(None)
            return

        MAX_FRAGMENT = 0x3000 # lots of slop here

        if len(msg) > MAX_FRAGMENT:
            # fragment
            i = 0
            while True:
                piece = msg[i * MAX_FRAGMENT:(i + 1) * MAX_FRAGMENT]
                if len(piece) == 0:
                    break
                self.write_plaintext(piece)
                i += 1
            return

        server_response = Message(type = ContentType.ApplicationData,
                                  version = self.version,
                                  body = msg)

        self.suite.encrypt(server_response)
        self.send(server_response)

