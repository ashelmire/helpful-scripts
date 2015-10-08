#!/usr/bin/env python
# Python RC4 implementation
# used to decode a lot of malware implementations of rc4 with base64-ness.

import sys
import base64
import argparse
import logging

logging.basicConfig(
    format='[%(asctime)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)
logging.getLogger('requests').setLevel(logging.WARNING)
log = logging.getLogger(__name__)


def ksa(key):
    '''
    RC4 Key Scheduling Algorithm

    arguments:
    key - initial key

    returns:
    s - scheduling array
    '''
    keylength = len(key)

    S = range(256)

    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        # swap S[i] and S[j]
        S[i], S[j] = S[j], S[i]

    return S


def prga(s):
    '''
    rc4 pseudo(not really) random number generation algorithm

    arguments:
    s - key scheduling array from ksa
    returns:
    keystream
    '''
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]  # swap

        keystream = s[(s[i] + s[j]) % 256]
        yield keystream


def convert_key(key):
    '''
    convert string key to int
    '''
    return [ord(c) for c in key]


def rc4(ciphertext, key):
    '''
    RC4 implementation of RC4

    RC4 arguments:
    ciphertext - the ciphertext to encrypt
    key - the key with which to generate the keystream
    '''
    key = convert_key(key)
    s = ksa(key)
    keystream = prga(s)
    # pt = ct ^ ks
    pt = []
    for c in ciphertext:
        pt.append(str(ord(c) ^ keystream.next()))
    return ''.join(pt)


def winrc4(ciphertext, key):
    '''
    winrc4:
        decode RC4 encoded ciphertext via WINAPI with passphrase key used to
        derive the RC4 key.
    '''
    try:
        from wincrypto import CryptCreateHash, CryptHashData, CryptDeriveKey, CryptEncrypt, CryptDecrypt
        from wincrypto.constants import CALG_RC4, CALG_MD5
    except:
        log.error('git clone https://github.com/crappycrypto/wincrypto for wincrypto')
        sys.exit()
    md5 = CryptCreateHash(CALG_MD5)
    CryptHashData(md5, key)
    rc4_key = CryptDeriveKey(md5, CALG_RC4)
    pt = CryptDecrypt(rc4_key, ciphertext)
    return pt

def main():
    opt = argparse.ArgumentParser(description='python rc4 implementation')
    opt.add_argument(
        '-k', '--key', help='The RC4 key', required=True)
    opt.add_argument(
        '-f', '--file', help='A file with ciphertext',
        required=True)
    opt.add_argument(
        '-b', '--base64', help='Convert ciphertext from base64',
        action='store_true')
    opt.add_argument(
        '-p', '--pbase64', help='Convert plaintext from base64',
        action='store_true')
    opt.add_argument(
        '-o', '--outfile',
        help='write output to outfile instead of stdout')
    opt.add_argument(
        '-w', '--winapi', action='store_true',
        help='Use WinCrypto API for RC4\n key is the password used to derive the key')

    options = opt.parse_args()
    key = options.key

    if options.base64:
        fh = base64.b64decode(open(options.file, 'r').read())
    else:
        ciphertext = open(options.file, 'rb').read()

    plaintext = None
    if options.winapi:
        plaintext = winrc4(ciphertext, key)
    else:
        plaintext = rc4(ciphertext, key)

    if plaintext:
        if options.pbase64:
            plaintext = base64.b64decode(plaintext)

        if options.outfile:
            of = open(option.outfile, 'wb')
            of.write(plaintext)
            of.close()
        else:
            print plaintext

if __name__ == '__main__':
    main()
