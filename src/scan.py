from tls import *
import json

class output:
    def __init__(self):
        self.ciphersuite = None
        self.recvd = []

    def to_json(self):
        return dict(ciphersuite = self.ciphersuite,
                    recvd = [x.to_json() for x in self.recvd])

def client_handshake(res, hello):
    m = (yield hello)
    assert m is None

    m = (yield None)
    res.recvd.append(m)
    
    if m.type == ContentType.Handshake and not m.opaque and m.body.type == HandshakeType.ServerHello:
        res.ciphersuite = m.body.body.ciphersuite

def probe(hostname, port):
    # tls1.0 first
    with connect(hostname, port) as f:
        hello = exploratory_handshake(hostname,
                                      CipherSuite.chrome_default_set(),
                                      ProtocolVersion.TLSv1_0)
        tls1 = output()
        protocol = client_handshake(tls1, hello)
        run_protocol(f, protocol)
    
    # now downgrade
    with connect(hostname, port) as f:
        hello = exploratory_handshake(hostname,
                                      CipherSuite.chrome_fallback_set(),
                                      ProtocolVersion.SSLv3)
        ssl3 = output()
        protocol = client_handshake(ssl3, hello)
        run_protocol(f, protocol)

    if tls1.ciphersuite:
        print('for', hostname, 'we chose', CipherSuite.tostring(tls1.ciphersuite), 'for tls1')
    if ssl3.ciphersuite:
        print('for', hostname, 'we chose', CipherSuite.tostring(ssl3.ciphersuite), 'for ssl3')
    return tls1.to_json(), ssl3.to_json()

def test(hostname):
    PORT = 443
    try:
        tls1, ssl3 = probe(hostname, PORT)
        return [hostname, PORT, 'supported', tls1, ssl3]
    except socket.timeout:
        return [hostname, PORT, 'timeout']
    except socket.error:
        return [hostname, PORT, 'not-listening']

if __name__ == '__main__':    
    for line in open('top-1m.csv'):
        line = line.strip()
        if not line:
            continue

        rank, hostname = line.split(',')
        rank = int(rank)
        hostname = 'www.' + hostname
        outf = 'results/{0:08d}-{1}.txt'.format(rank, hostname)
        if os.path.exists(outf):
            continue

        print('test', hostname)
        result = test(hostname)
        json.dump(dict(rank = rank,
                       hostname = hostname,
                       result = result),
                  open(outf, 'w'))
