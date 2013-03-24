import io

class Decode:
    @staticmethod
    def u8(b):
        assert len(b) == 1
        return b[0]
    
    @staticmethod
    def u16(b):
        assert len(b) == 2
        return b[0] << 8 | b[1]

    @staticmethod
    def u24(b):
        assert len(b) == 3
        return b[0] << 16 | b[1] << 8 | b[2]

    @staticmethod
    def u32(b):
        assert len(b) == 4
        return b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]

class Read:
    @staticmethod
    def must(f, n):
        x = f.read(n)
        if x is None:
            raise IOError('{0} bytes not available from non-blocking file {1}'.format(n, f))
        if len(x) != n:
            raise IOError('short read from {0}: wanted {1} bytes, got {2}'.format(f, n, len(x)))
        return x
    
    u8 = lambda f: Decode.u8(Read.must(f, 1))
    u16 = lambda f: Decode.u16(Read.must(f, 2))
    u24 = lambda f: Decode.u24(Read.must(f, 3))
    u32 = lambda f: Decode.u32(Read.must(f, 4))

    @staticmethod
    def vec(f, lenf, itemf):
        o = []

        # take length and read in whole body
        ll = lenf(f)
        body_bytes = Read.must(f, ll)

        bodyf = io.BytesIO(body_bytes)
        while bodyf.tell() != ll:
            o.append(itemf(bodyf))
        
        return o

class Encode:
    @staticmethod
    def u8(v):
        assert v >= 0 and v <= 0xff
        return [ v ]
    
    @staticmethod
    def u16(v):
        assert v >= 0 and v <= 0xffff
        return [ v >> 8 & 0xff, v & 0xff ]

    @staticmethod
    def u24(v):
        assert v >= 0 and v <= 0xffffff
        return [ v >> 16 & 0xff, v >> 8 & 0xff, v & 0xff ]

    @staticmethod
    def u32(v):
        assert v >= 0 and v <= 0xffffffff
        return [ v >> 24 & 0xff, v >> 16 & 0xff, v >> 8 & 0xff, v & 0xff ]

    @staticmethod
    def item_vec(lenf, itemf, items):
        body = []
        for x in items:
            body.extend(itemf(x))
        return lenf(len(body)) + body

    @staticmethod
    def vec(lenf, items):
        body = []
        for x in items:
            body.extend(x.encode())
        return lenf(len(body)) + body

class Struct:
    def __bytes__(self):
        return bytes(self.encode())

    @classmethod
    def decode(cls, b, *args, **kwargs):
        f = io.BytesIO(b)
        r = cls.read(f, *args, **kwargs)
        return r

    def __repr__(self):
        return str(self)

    def __str__(self):
        o = []
        for k in sorted(self.__dict__.keys()):
            if k[0] == '_':
                continue
            o.append('{0} = {1}'.format(k, self.__dict__[k]))
        return '<{0} {1}>'.format(self.__class__.__name__, ', '.join(o))

class Enum:
    @classmethod
    def read(cls, f):
        v = Read.must(f, cls._ByteSize)
        v = cls._Decode(v)
        cls.lookup(v)
        return v

    @classmethod
    def table(cls):
        d = {}
        for k, v in cls.__dict__.items():
            if not k.isidentifier() or k[0] == '_' or k == 'MAX':
                continue
            if v in d:
                raise ValueError('{0} has more than one mapping for value {1:x} (at least {2!r} and {3!r})'.format(cls.__name__, v, d[v], k))
            d[v] = k
        return d
    
    @classmethod
    def lookup(cls, value):
        if value > cls.MAX:
            raise ValueError('{0:x} cannot be decoded as a {1}: too large'.format(value, cls.__name__))

        d = cls.table()
        if value in d:
            return d[value]

        raise ValueError('{0:x} cannot be decoded as a {1}: unknown value'.format(value, cls.__name__))

    @classmethod
    def tostring(cls, value):
        name = cls.lookup(value)
        return '<{0} {1} ({2:x})>'.format(cls.__name__, name, value)

    @classmethod
    def to_json(cls, value):
        return [value, cls.__name__, cls.lookup(value)]

    @classmethod
    def encode(cls, value):
        return cls._Encode(value)

    @classmethod
    def all(cls):
        return [value for value, name in cls.table().items()]

class Enum8(Enum):
    _ByteSize = 1
    _Encode = Encode.u8
    _Decode = Decode.u8

class Enum16(Enum):
    _ByteSize = 2
    _Encode = Encode.u16
    _Decode = Decode.u16
