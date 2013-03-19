from base import Enum16

suites = {}

with open('ciphersuites.txt') as f:
    for l in f:
        name, suite = l.strip().split(' = ')
        suite = int(suite, 16)
        suites[suite] = name

class CipherSuite(Enum16):
    MAX = 0xffff

    @staticmethod
    def table():
        return suites
