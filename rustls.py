import tls.protocol_types as TY
import tls.base as BASE

start_enums = """
use msgs::codec::{encode_u8, read_u8, encode_u16, read_u16, Reader, Codec};"""

enum_def = """
#[derive(Debug, PartialEq, Eq, Clone)]
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

print(start_enums)
convert_enum(TY.ProtocolVersion)
convert_enum(TY.HashAlgorithm)
convert_enum(TY.SignatureAlgorithm)
convert_enum(TY.ClientCertificateType)
convert_enum(TY.Compression)
convert_enum(TY.ContentType)
convert_enum(TY.HandshakeType)
convert_enum(TY.AlertLevel)
convert_enum(TY.AlertDescription)
convert_enum(TY.HeartbeatMessageType)
convert_enum(TY.ExtensionType)
convert_enum(TY.ServerNameType)
convert_enum(TY.NamedCurve)
convert_enum(TY.CipherSuite)
convert_enum(TY.ECPointFormat)
convert_enum(TY.HeartbeatMode)
convert_enum(TY.ECCurveType)
