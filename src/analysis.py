import glob
import json

statuses = {}
weird_hosts = []
successes = {True: 0, False: 0}
tls1_count = dict(successes)
ssl3_count = dict(successes)
downgrades = dict(successes)
downgrade_detail = {}

INDEX = 0
TYPE = 1
NAME = 2

def get_ciphersuite(m):
    if m['ciphersuite'] == None:
        return None

    msg = m['recvd'][0]
    if msg['type'][NAME] != 'Handshake':
        return None
    if msg['body']['type'][NAME] != 'ServerHello':
        return None
    return msg['body']['body']['ciphersuite'][NAME]

def bool_percent(v):
    tot = v[True] + v[False]
    pc = '({0:g}%)'.format(100 * v[True] / tot)
    return '{0}/{1} {2}'.format(v[True], tot, pc)

if __name__ == '__main__':
    for f in glob.glob('results/*.txt'):
        o = json.load(open(f, 'r'))
        r = o['result']
        if o['rank'] == 501:
            break
        hostname, port, status = r[0:3]
        statuses[status] = statuses.get(status, 0) + 1

        success = False

        if status == 'supported':
            tls1, ssl3 = r[3:5]
            cs_tls1 = get_ciphersuite(tls1)
            cs_ssl3 = get_ciphersuite(ssl3)

            if cs_tls1 or cs_ssl3:
                success = True

            tls1_count[bool(cs_tls1)] = tls1_count.get(bool(cs_tls1), 0) + 1
            ssl3_count[bool(cs_ssl3)] = ssl3_count.get(bool(cs_ssl3), 0) + 1

            if cs_tls1 and cs_ssl3:
                downgrade = cs_tls1 != cs_ssl3
                downgrades[downgrade] = downgrades.get(downgrade, 0) + 1

                if downgrade:
                    key = (cs_tls1, cs_ssl3)
                    downgrade_detail[key] = downgrade_detail.get(key, 0) + 1
            else:
                weird_hosts.append(hostname)
                
        successes[success] = successes.get(success, 0) + 1

    print('corpus size', sum(statuses.values()))
    print('tls1 support', bool_percent(tls1_count))
    print('ssl3 support', bool_percent(ssl3_count))
    print('statuses', statuses)
    print('downgrades', bool_percent(downgrades))

    for pair, count in downgrade_detail.items():
        print('downgrades from', pair[0], '->', pair[1], ':', count)

    print('investigate hosts', weird_hosts)
