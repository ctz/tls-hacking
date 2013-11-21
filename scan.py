from tls.tls import *
import socket
import json
import sys

class output:
    def __init__(self):
        self.hello = None
        self.ciphersuite = None
        self.recvd = []

    def to_json(self):
        return dict(ciphersuite = self.ciphersuite,
                    hello = self.hello.to_json(),
                    recvd = [x.to_json() for x in self.recvd])

class client_handshake:
    def __init__(self, result, hellomsg):
        self.result = result
        self.outgoing = [hellomsg]
        
    def flush(self):
        out = self.outgoing
        self.outgoing = []
        return out
        
    def incoming(self, m):
        m.interpret_body()
        self.result.recvd.append(m)
    
        if m.type == ContentType.Handshake and m.body.type == HandshakeType.ServerHello:
            self.result.ciphersuite = m.body.body.ciphersuite
            self.result.hello = m
            self.outgoing = [ None ]

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

def is_error(result):
    return result[2] != 'supported'

def completed_handshake(x):
    return x['ciphersuite']
    
def test(hostname):
    PORT = 443
    try:
        tls1, ssl3 = probe(hostname, PORT)
        if completed_handshake(tls1) or completed_handshake(ssl3):
            return [hostname, PORT, 'supported', tls1, ssl3]
        else:
            return [hostname, PORT, 'failed-handshake']
    except socket.timeout:
        return [hostname, PORT, 'timeout']
    except socket.error as e:
        print(e)
        return [hostname, PORT, 'not-listening']

if __name__ == '__main__':
    if len(sys.argv) == 2:
        filter = sys.argv[-1]
    else:
        filter = None

    for line in open('top-1k.csv'):
        line = line.strip()
        if not line:
            continue
        if filter and filter not in line:
            continue

        rank, hostname = line.split(',')
        rank = int(rank)
        
        for host, final in ((hostname, False), ('www.' + hostname, True)):
            outf = 'results/{0:08d}-{1}.txt'.format(rank, host)

            print('test', host)
            result = test(host)
            if final or not is_error(result):
                json.dump(dict(rank = rank,
                               hostname = host,
                               result = result),
                          open(outf, 'w'),
                          sort_keys = True,
                          indent = '  '
                          )
                break
