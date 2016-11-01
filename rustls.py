import tls.protocol_types as TY
import tls.base as BASE
import sys

start_enums = """
use msgs::codec::{encode_u8, read_u8, encode_u16, read_u16, Reader, Codec};"""

enum_def = """
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum %(name)s {
%(enum_items)s
  Unknown(%(underlying_type)s)
}

impl Codec for %(name)s {
  fn encode(&self, bytes: &mut Vec<u8>) {
    %(encode)s;
  }

  fn read(r: &mut Reader) -> Option<%(name)s> {
    let u = %(decode)s;

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
%(match_int_enum)s
      x => %(name)s::Unknown(x)
    })
  }
}

impl %(name)s {
  pub fn get_%(underlying_type)s(&self) -> %(underlying_type)s {
    match *self {
%(match_enum_int)s
      %(name)s::Unknown(v) => v
    }
  }
}"""

def convert_enum(ty):
    table = ty.table()
    items = list(table.items())
    items = list(filter(lambda x: isinstance(x[0], int), items))
    items.sort(key = lambda x: x[0])

    name = ty.__name__

    if issubclass(ty, BASE.Enum8):
        underlying_type = 'u8'
        encode = 'encode_u8(self.get_u8(), bytes)'
        decode = 'read_u8(r)'
        val_format = lambda x: '0x%02x' % x
    else:
        underlying_type = 'u16'
        encode = 'encode_u16(self.get_u16(), bytes)'
        decode = 'read_u16(r)'
        val_format = lambda x: '0x%04x' % x

    enum_items = '\n'.join('  %s,' % x for _, x in items)
    match_enum_int = '\n'.join('      %s::%s => %s,' % (name, item, val_format(value)) for value, item in items)
    match_int_enum = '\n'.join('      %s => %s::%s,' % (val_format(value), name, item) for value, item in items)

    data = dict(
            name = name,
            enum_items = enum_items,
            underlying_type = underlying_type,
            encode = encode,
            decode = decode,
            match_enum_int = match_enum_int,
            match_int_enum = match_int_enum
            )

    print(enum_def % data)

def test_enum(ty):
    name = ty.__name__
    table = ty.table()
    items = list(table.items())
    items = list(filter(lambda x: isinstance(x[0], int), items))
    items.sort(key = lambda x: x[0])

    first, last = items[0][1], items[-1][1]

    if issubclass(ty, BASE.Enum8):
        test_fn = 'test_enum8'
    else:
        test_fn = 'test_enum16'

    print('%(test_fn)s::<%(name)s>(%(name)s::%(first)s, %(name)s::%(last)s);' %
            locals())

types = [
    TY.ProtocolVersion,
    TY.HashAlgorithm,
    TY.SignatureAlgorithm,
    TY.ClientCertificateType,
    TY.Compression,
    TY.ContentType,
    TY.HandshakeType,
    TY.AlertLevel,
    TY.AlertDescription,
    TY.HeartbeatMessageType,
    TY.ExtensionType,
    TY.ServerNameType,
    TY.NamedCurve,
    TY.NamedGroup,
    TY.CipherSuite,
    TY.ECPointFormat,
    TY.HeartbeatMode,
    TY.ECCurveType,
    TY.SignatureScheme,
    TY.PSKKeyExchangeMode,
    TY.KeyUpdateRequest,
]

if sys.argv[-1] == 'test':
    for ty in types:
        test_enum(ty)
else:
    print(start_enums)
    for ty in types:
        convert_enum(ty)
