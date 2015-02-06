tls-hacking
===========

Assorted TLS experimentation in python.  This has a working TLS1.0 client and server in pure python.
It supports AES+HMAC and RC4 transport encryption and static RSA ciphersuites only.

You should only use this for network testing.  It is *not* suitable for production use.
To be specific: TLS1.0 is obsolete, no implemented ciphersuites provide forward secrecy,
   RC4 is broken, the TLS AES ciphersuite is impossible to implement, etc etc.


