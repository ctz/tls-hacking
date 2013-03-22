import time
import os
import io

from base import Enum8, Enum16, Decode, Encode, Read, Struct

class ProtocolVersion(Enum16):
    SSLv2 = 0x0200
    SSLv3 = 0x0300
    TLSv1_0 = 0x0301
    TLSv1_1 = 0x0302
    TLSv1_2 = 0x0303
    MAX = 0xffff

    _Highest = TLSv1_2

from ciphersuites import CipherSuite

class Compression(Enum8):
    Null = 0
    Deflate = 1
    LSZ = 64
    MAX = 0xff
    
    @staticmethod
    def all():
        return [ Compression.Deflate, Compression.LSZ, Compression.Null ]

class ContentType(Enum8):
    ChangeCipherSpec = 20
    Alert = 21
    Handshake = 22
    ApplicationData = 23
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
    NoRenegotiaion = 100
    UnsupportedExtension = 110
    MAX = 255

class Alert(Struct):
    def __init__(self, level = AlertLevel.MAX, desc = AlertDescription.MAX):
        Struct.__init__(self)
        self.level = level
        self.desc = desc

    def encode(self):
        return AlertLevel.encode(self.level) + AlertDescription.encode(self.desc)

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

    @staticmethod
    def read(f):
        a = ApplicationData()
        a.data = f.read()
        return a

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

    def read_body(self, f):
        ll = Read.u24(f)
        body_bytes = Read.must(f, ll)

        decoders = {
            HandshakeType.ClientHello: ClientHello.decode,
            HandshakeType.ServerHello: ServerHello.decode,
            HandshakeType.Certificate: Certificate.decode,
            HandshakeType.ServerHelloDone:  ServerHelloDone.decode
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

    @staticmethod
    def read(f):
        e = Extension()
        e.type = ExtensionType.read(f)
        e.data = Read.vec(f, Read.u16, Read.u8)
        return e

class ServerNameExtensionBody(Struct):
    def __init__(self, names = None):
        Struct.__init__(self)
        self.names = names if names else []

    def encode(self):
        return Encode.vec(Encode.u16, self.names)

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

    @staticmethod
    def read(f):
        return EllipticCurvesExtensionBody(Read.vec(f, Read.u16, NamedCurve.read))
    
    @staticmethod
    def all_named_curves():
        return EllipticCurvesExtensionBody(list(range(NamedCurve.sect163k1,
                                                      NamedCurve.secp521r1 + 1)))


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
        o.extend(Encode.vec(Encode.u8, self.session_id))
        o.extend(Encode.item_vec(Encode.u16, CipherSuite._Encode, self.ciphersuites))
        o.extend(Encode.item_vec(Encode.u8, Compression._Encode, self.compressions))
        if len(self.extensions):
            o.extend(Encode.vec(Encode.u16, self.extensions))
        return o

    @staticmethod
    def read(f):
        c = ClientHello()
        c.version = ProtocolVersion.read(f)
        c.random = Random.read(f)
        c.session_id = Read.vec(f, Read.u8, Read.u8)
        c.ciphersuites = Read.vec(f, Read.u16, CipherSuite.read)
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
    def encode(self):
        return []
    @staticmethod
    def read(f):
        return ServerHelloDone()

class ASN1Cert(Struct):
    def __init__(self, data = None):
        Struct.__init__(self)
        self.data = data

    def encode(self):
        return Encode.item_vec(Encode.u24, Encode.u8, self.data)

    @staticmethod
    def read(f):
        ac = ASN1Cert()
        ac.data = Read.vec(f, Read.u24, Read.u8)
        return ac

class Certificate(Struct):
    def __init__(self, certs = None):
        Struct.__init__(self)
        self.certs if certs else []

    def encode(self):
        return Encode.item_vec(Encode.u24, ASN1Cert.encode, self.certs)

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

    @staticmethod
    def read(f):
        m = Message()
        m.type = ContentType.read(f)
        m.version = ProtocolVersion.read(f)
        m.read_body(f)
        return m

    def read_body(self, f):
        ll = Read.u16(f)
        body_bytes = Read.must(f, ll)

        decoders = {
            ContentType.Alert: Alert.decode,
            ContentType.ApplicationData: ApplicationData.decode,
            ContentType.ChangeCipherSpec: ChangeCipherSpec.decode,
            ContentType.Handshake: Handshake.decode
        }

        assert decoders.keys() == ContentType.table().keys()
        self.body = decoders[self.type](body_bytes)

    def encode(self):
        body = bytes(self.body)
        return ContentType.encode(self.type) + \
               ProtocolVersion.encode(self.version) + \
               Encode.u16(len(body)) + \
               list(body)

