import time
import os
import io

from logging import debug

from .base import Enum8, Enum16, Decode, Encode, Read, Struct

def bytes_or_json(v):
    if hasattr(v, 'to_json'):
        return v.to_json()
    else:
        return ['hex', ''.join('{0:02x}'.format(x) for x in bytes(v))]

class ProtocolVersion(Enum16):
    SSLv2 = 0x0200
    SSLv3 = 0x0300
    TLSv1_0 = 0x0301
    TLSv1_1 = 0x0302
    TLSv1_2 = 0x0303
    MAX = 0xffff

    _Highest = TLSv1_2

from .ciphersuites import CipherSuite

class HashAlgorithm(Enum8):
    NONE = 0
    MD5 = 1
    SHA1 = 2
    SHA224 = 3
    SHA256 = 4
    SHA384 = 5
    SHA512 = 6

class SignatureAlgorithm(Enum8):
    Anonymous = 0
    RSA = 1
    DSA = 2
    ECDSA = 3

class ClientCertificateType(Enum8):
    RSASign = 1
    DSSSign = 2
    RSAFixedDH = 3
    DSSFixedDH = 4
    RSAEphemeralDH = 5
    DSSEphemeralDH = 6
    FortezzaDMS = 20

class Compression(Enum8):
    Null = 0
    Deflate = 1
    LSZ = 64
    MAX = 0xff
    
    @staticmethod
    def all():
        return [ Compression.Deflate, Compression.LSZ, Compression.Null ]
    
    @staticmethod
    def none():
        return [ Compression.Null ]

class ContentType(Enum8):
    ChangeCipherSpec = 20
    Alert = 21
    Handshake = 22
    ApplicationData = 23
    Heartbeat = 24
    MAX = 0xff

class HandshakeType(Enum8):
    HelloRequest = 0
    ClientHello = 1
    ServerHello = 2
    Certificate = 11
    ServerKeyExchange = 12
    CertificateRequest = 13
    ServerHelloDone = 14
    CertificateVerify = 15
    ClientKeyExchange = 16
    Finished = 20
    CertificateURL = 21
    CertificateStatus = 22
    MAX = 0xff

class ChangeCipherSpec(Struct):
    def __init__(self):
        Struct.__init__(self)

    def encode(self):
        return Encode.u8(1)

    def to_json(self):
        return dict(value = 1)

    @staticmethod
    def read(b):
        value = Read.u8(b)
        if value != 1:
            raise ValueError('ChangeCipherSpec payload incorrect')
        return ChangeCipherSpec()

class AlertLevel(Enum8):
    Warning = 1
    Fatal = 2
    MAX = 0xff

class AlertDescription(Enum8):
    CloseNotify = 0
    UnexpectedMessage = 10
    BadRecordMac = 20
    DecryptionFailed = 21
    RecordOverflow = 22
    DecompressionFailure = 30
    HandshakeFailure = 40
    NoCertificate = 41
    BadCertificate = 42
    UnsupportedCertificate = 43
    CertificateRevoked = 44
    CertificateExpired = 45
    CertificateUnknown = 46
    IllegalParameter = 47
    UnknownCA = 48
    AccessDenied = 49
    DecodeError = 50
    DecryptError = 51
    ExportRestriction = 60
    ProtocolVersion = 70
    InsufficientSecurity = 71
    InternalError = 80
    UserCanceled = 90
    NoRenegotiation = 100
    UnsupportedExtension = 110
    UnrecognisedName = 112
    MAX = 255

class Alert(Struct):
    def __init__(self, level = AlertLevel.MAX, desc = AlertDescription.MAX):
        Struct.__init__(self)
        self.level = level
        self.desc = desc

    def encode(self):
        return AlertLevel.encode(self.level) + AlertDescription.encode(self.desc)

    def to_json(self):
        return dict(level = AlertLevel.to_json(self.level),
                    desc = AlertDescription.to_json(self.desc))

    @staticmethod
    def read(f):
        a = Alert()
        a.level = AlertLevel.read(f)
        a.desc = AlertDescription.read(f)
        return a

class ApplicationData(Struct):
    def __init__(self, data = None):
        Struct.__init__(self)
        self.data = data

    def encode(self):
        return bytes(self.data)

    def to_json(self):
        return dict(data = self.data)

    @staticmethod
    def read(f):
        return ApplicationData(data = f.read())

class ECPointFormat(Enum8):
    Uncompressed = 0
    ANSIX962CompressedPrime = 1
    ANSIX962CompressedChar2 = 2
    MAX = 255

class HeartbeatMessageType(Enum8):
    Request = 1
    Response = 2
    MAX = 255

class Heartbeat(Struct):
    def __init__(self, type = None, payload = None):
        Struct.__init__(self)
        self.type = type
        self.payload = payload
        self.bytes_remain = 0

    def append_fragment(self, other):
        assert other.type == ContentType.Heartbeat
        extra, self.bytes_remain = Read.partial(io.BytesIO(other.body), self.bytes_remain)
        self.payload += extra

    def is_fully_received(self):
        return self.bytes_remain == 0

    def encode(self):
        return HeartbeatMessageType.encode(self.type) + \
               Encode.u16(len(self.payload)) + \
               list(self.payload)

    def to_json(self):
        return dict(type = HeartbeatMessageType.to_json(self.type),
                    payload = bytes_or_json(self.payload))
    
    @staticmethod
    def read(f):
        h = Heartbeat()
        h.type = HeartbeatMessageType.read(f)
        ll = Read.u16(f)
        print('heartbeat len is %d' % ll)
        h.payload, h.bytes_remain = Read.partial(f, ll)
        return h

class Handshake(Struct):
    def __init__(self, type, body):
        Struct.__init__(self)
        self.type = type
        self.body = body

    def encode(self):
        body = bytes(self.body)
        return HandshakeType.encode(self.type) + \
               Encode.u24(len(body)) + \
               list(body)

    def to_json(self):
        return dict(type = HandshakeType.to_json(self.type),
                    body = bytes_or_json(self.body))

    def read_body(self, f):
        ll = Read.u24(f)
        body_bytes = Read.must(f, ll)

        decoders = {
            HandshakeType.ClientHello: ClientHello.decode,
            HandshakeType.ServerHello: ServerHello.decode,
            HandshakeType.Certificate: Certificate.decode,
            HandshakeType.ServerHelloDone: ServerHelloDone.decode,
            HandshakeType.ClientKeyExchange: ClientKeyExchange.decode,
            HandshakeType.ServerKeyExchange: ServerKeyExchange.decode,
            HandshakeType.Finished: Finished.decode,
        }

        if self.type not in decoders:
            raise NotImplementedError('do not yet know how to decode {0}'.format(HandshakeType.tostring(self.type)))

        self.body = decoders[self.type](body_bytes)

    @staticmethod
    def read(f):
        h = Handshake(None, None)
        h.type = HandshakeType.read(f)
        h.read_body(f)
        return h

class Random(Struct):
    NONCE_LEN = 28
    
    def __init__(self, utctime = None, nonce = None):
        Struct.__init__(self)
        self.time = utctime
        self.nonce = nonce

    def encode(self):
        return Encode.u32(self.time) + list(self.nonce)

    def to_json(self):
        return dict(time = self.time,
                    nonce = bytes_or_json(self.nonce))

    @staticmethod
    def read(f):
        return Random(Read.u32(f), Read.must(f, Random.NONCE_LEN))

    @staticmethod
    def generate():
        return Random(int(time.time()), os.urandom(Random.NONCE_LEN))

class ExtensionType(Enum16):
    ServerName = 0
    MaxFragmentLength = 1
    ClientCertificateUrl = 2
    TrustedCAKeys = 3
    TruncatedHMAC = 4
    StatusRequest = 5
    UserMapping = 6
    ClientAuthz = 7
    ServerAuthz = 8
    CertificateType = 9
    EllipticCurves = 10
    ECPointFormats = 11
    SRP = 12
    SignatureAlgorithms = 13
    UseSRTP = 14
    Heartbeat = 15
    Padding = 21 # http://tools.ietf.org/html/draft-agl-tls-padding-03
    SessionTicket = 35
    NextProtocolNegotiation = 0x3374
    ChannelId = 0x754f
    RenegotiationInfo = 0xff01
    
    MAX = 0xffff

class Extension(Struct):
    def __init__(self, type = None, data = None):
        Struct.__init__(self)
        self.type = type
        self.data = data

    def encode(self):
        body = bytes(self.data)
        return ExtensionType.encode(self.type) + \
               Encode.u16(len(body)) + \
               list(body)

    def to_json(self):
        return dict(type = ExtensionType.to_json(self.type),
                    body = bytes_or_json(self.data))

    @staticmethod
    def read(f):
        e = Extension()
        e.type = ExtensionType.read(f, lax_enum = True)
        e.data = Read.vec(f, Read.u16, Read.u8)
        return e

class ServerNameExtensionBody(Struct):
    def __init__(self, names = None):
        Struct.__init__(self)
        self.names = names if names else []

    def encode(self):
        return Encode.vec(Encode.u16, self.names)

    def to_json(self):
        return [x.to_json() for x in self.names]

    @staticmethod
    def read(f):
        return ServerNameExtensionBody(Read.vec(f, Read.u16, ServerName.read))

class ServerNameType(Enum8):
    HostName = 0
    MAX = 0xff

class ServerName(Struct):
    def __init__(self, type, body):
        Struct.__init__(self)
        self.type = type
        self.body = body

    def encode(self):
        return ServerNameType.encode(self.type) + \
               Encode.item_vec(Encode.u16, Encode.u8, self.body)

    def to_json(self):
        return dict(type = ServerNameType.to_json(self.type),
                    body = bytes_or_json(self.body))
    
    @staticmethod
    def hostname(h):
        return ServerName(ServerNameType.HostName, bytes(h, 'utf-8'))
    
    @staticmethod
    def read(f):
        sn = ServerName(None, None)
        sn.type = ServerNameType.read(f)
        sn.body = Read.vec(f, Read.u16, Read.u8)
        return sn

class NamedCurve(Enum16):
    sect163k1 = 1
    sect163r1 = 2
    sect163r2 = 3
    sect193r1 = 4
    sect193r2 = 5
    sect233k1 = 6
    sect233r1 = 7
    sect239k1 = 8
    sect283k1 = 9
    sect283r1 = 10
    sect409k1 = 11
    sect409r1 = 12
    sect571k1 = 13
    sect571r1 = 14
    secp160k1 = 15
    secp160r1 = 16
    secp160r2 = 17
    secp192k1 = 18
    secp192r1 = 19
    secp224k1 = 20
    secp224r1 = 21
    secp256k1 = 22
    secp256r1 = 23
    secp384r1 = 24
    secp521r1 = 25
    arbitrary_explicit_prime_curves = 0xFF01
    arbitrary_explicit_char2_curves = 0xFF02

    MAX = 0xffff

class EllipticCurvesExtensionBody(Struct):
    def __init__(self, curves = None):
        Struct.__init__(self)
        self.curves = curves if curves else []

    def encode(self):
        return Encode.item_vec(Encode.u16, NamedCurve._Encode, self.curves)

    def to_json(self):
        return [NamedCurve.to_json(x) for x in self.curves]

    @staticmethod
    def read(f):
        return EllipticCurvesExtensionBody(Read.vec(f, Read.u16, NamedCurve.read))
    
    @staticmethod
    def all_named_curves():
        return EllipticCurvesExtensionBody(list(range(NamedCurve.sect163k1,
                                                      NamedCurve.secp521r1 + 1)))

    @staticmethod
    def all_common_prime_curves():
        return EllipticCurvesExtensionBody([NamedCurve.secp256r1,
                                            NamedCurve.secp384r1,
                                            NamedCurve.secp521r1])
    


class ClientHello(Struct):
    def __init__(self, version = None, random = None, session_id = None,
                 ciphersuites = None, compressions = None, extensions = None):
        Struct.__init__(self)
        self.version = version if version else ProtocolVersion._Highest
        self.random = random if random else Random.generate()
        self.session_id = session_id if session_id else []
        self.ciphersuites = ciphersuites if ciphersuites else []
        self.compressions = compressions if compressions else []
        self.extensions = extensions if extensions else []

    def encode(self):
        o = []
        o.extend(ProtocolVersion.encode(self.version))
        o.extend(self.random.encode())
        o.extend(Encode.item_vec(Encode.u8, Encode.u8, self.session_id))
        o.extend(Encode.item_vec(Encode.u16, CipherSuite._Encode, self.ciphersuites))
        o.extend(Encode.item_vec(Encode.u8, Compression._Encode, self.compressions))
        if len(self.extensions):
            o.extend(Encode.vec(Encode.u16, self.extensions))
        return o

    def to_json(self):
        return dict(version = ProtocolVersion.to_json(self.version),
                    random = self.random.to_json(),
                    session_id = bytes_or_json(self.session_id),
                    ciphersuites = [CipherSuite.to_json(x) for x in self.ciphersuites],
                    compressions = [Compression.to_json(x) for x in self.compressions],
                    extensions = [x.to_json() for x in self.extensions])

    @staticmethod
    def read(f):
        c = ClientHello()
        c.version = ProtocolVersion.read(f)
        c.random = Random.read(f)
        c.session_id = Read.vec(f, Read.u8, Read.u8)
        c.ciphersuites = Read.vec(f, Read.u16, lambda f: CipherSuite.read(f, lax_enum = True))
        c.compressions = Read.vec(f, Read.u8, Compression.read)

        left = f.read()
        if len(left):
            c.extensions = Read.vec(io.BytesIO(left), Read.u16, Extension.read)
        
        return c

class ServerHello(Struct):
    def __init__(self, version = None, random = None, session_id = None, ciphersuite = None, compression = None, extensions = None):
        Struct.__init__(self)
        self.version = version
        self.random = random
        self.session_id = session_id
        self.ciphersuite = ciphersuite
        self.compression = compression
        self.extensions = extensions if extensions else []

    def encode(self):
        return ProtocolVersion.encode(self.version) + \
               self.random.encode() + \
               Encode.item_vec(Encode.u8, Encode.u8, self.session_id) + \
               CipherSuite.encode(self.ciphersuite) + \
               Compression.encode(self.compression) + \
               (Encode.vec(Encode.u16, self.extensions) if self.extensions else [])

    def to_json(self):
        return dict(version = ProtocolVersion.to_json(self.version),
                    random = self.random.to_json(),
                    session_id = bytes_or_json(self.session_id),
                    ciphersuite = CipherSuite.to_json(self.ciphersuite),
                    compression = Compression.to_json(self.compression),
                    extensions = [x.to_json() for x in self.extensions])

    @staticmethod
    def read(f):
        s = ServerHello()
        s.version = ProtocolVersion.read(f)
        s.random = Random.read(f)
        s.session_id = Read.vec(f, Read.u8, Read.u8)
        s.ciphersuite = CipherSuite.read(f)
        s.compression = Compression.read(f)

        left = f.read()
        if len(left):
            s.extensions = Read.vec(io.BytesIO(left), Read.u16, Extension.read)
            
        return s

class ServerHelloDone(Struct):
    def encode(self): return []
    def to_json(): return {}
    @staticmethod
    def read(f):
        return ServerHelloDone()

class ClientKeyExchange(Struct):
    def __init__(self, body = None):
        Struct.__init__(self)
        self.body = body if body else []
    
    def encode(self):
        return self.body

    def to_json(self):
        return bytes_or_json(self.body)
    
    @staticmethod
    def read(f):
        c = ClientKeyExchange()
        c.body = f.read()
        return c

class ServerKeyExchange(Struct):
    def __init__(self, body = None):
        Struct.__init__(self)
        self.body = body if body else []
    
    def encode(self):
        return self.body

    def to_json(self):
        return bytes_or_json(self.body)
    
    @staticmethod
    def read(f):
        c = ServerKeyExchange()
        c.body = f.read()
        return c

class Finished(Struct):
    def __init__(self, body = None):
        Struct.__init__(self)
        self.body = body if body else []
    
    def encode(self):
        return self.body

    def to_json(self):
        return bytes_or_json(self.body)
    
    @staticmethod
    def read(f):
        c = Finished()
        c.body = bytes([Read.u8(f) for _ in range(12)])
        return c

class ASN1Cert(Struct):
    def __init__(self, data = None):
        Struct.__init__(self)
        self.data = data

    def encode(self):
        return Encode.item_vec(Encode.u24, Encode.u8, self.data)

    def to_json(self):
        return bytes_or_json(self.data)

    @staticmethod
    def read(f):
        ac = ASN1Cert()
        ac.data = Read.vec(f, Read.u24, Read.u8)
        return ac

class Certificate(Struct):
    def __init__(self, certs = None):
        Struct.__init__(self)
        self.certs = certs if certs else []

    def encode(self):
        return Encode.item_vec(Encode.u24, ASN1Cert.encode, self.certs)

    def to_json(self):
        return [x.to_json() for x in self.certs]

    @staticmethod
    def read(f):
        c = Certificate()
        c.certs = Read.vec(f, Read.u24, ASN1Cert.read)
        return c

class Message(Struct):
    def __init__(self, type = 0, version = 0, body = None):
        Struct.__init__(self)
        self.type = type
        self.version = version
        self.body = body
        self.opaque = False

    @staticmethod
    def prefix_has_full_frame(b):
        lb = len(b)
        if lb < 5:
            return False
        fl = Decode.u16(b[3:5])
        return len(b) >= fl + 5

    @staticmethod
    def read(f, opaque = False):
        m = Message()
        m.type = ContentType.read(f)
        m.version = ProtocolVersion.read(f)
        m.read_body(f, opaque)
        return m

    def interpret_body(self):
        decoders = {
            ContentType.Alert: Alert.decode,
            ContentType.ApplicationData: ApplicationData.decode,
            ContentType.ChangeCipherSpec: ChangeCipherSpec.decode,
            ContentType.Handshake: Handshake.decode,
            ContentType.Heartbeat: Heartbeat.decode
        }

        assert decoders.keys() == ContentType.table().keys()
        self.body = decoders[self.type](self.body)
        self.opaque = False

    def read_body(self, f, opaque):
        ll = Read.u16(f)
        self.body = Read.must(f, ll)
        self.opaque = opaque

        if not self.opaque:
            self.interpret_body()

    def encode(self):
        return bytes(self.header()) + bytes(self.body)

    def header(self):
        # the stuff which gets put into the mac (minus sequence number and body)
        return ContentType.encode(self.type) + \
               ProtocolVersion.encode(self.version) + \
               Encode.u16(len(bytes(self.body)))

    def to_json(self):
        return dict(type = ContentType.to_json(self.type),
                    version = ProtocolVersion.to_json(self.version),
                    body = bytes_or_json(self.body))
                    

