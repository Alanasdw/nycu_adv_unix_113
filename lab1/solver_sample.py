#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from pwn import *
import zlib
from itertools import permutations
# from solpow import solve_pow
import base64
import hashlib
import time

LOCAL_VERSION = './given/guess.dist.py'
DIGIT_COUNT = 4
ALL_NUMBERS_LIST = [''.join(p) for p in permutations('0123456789', DIGIT_COUNT)]

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    print(time.time(), "solving pow ...")
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h[:6] == '000000':
            solved = str(i).encode()
            print("solved =", solved)
            break
    print(time.time(), "done.")
    r.sendlineafter(b'string S: ', base64.b64encode(solved))
    z = r.recvline(); print(z.decode().strip())
    z = r.recvline(); print(z.decode().strip())

def recv( r):
    given = r.recvline()

    given = given.decode()
    # print( "given after decode:", given)
    given = given.split()[ 1]
    # print( "given after split[1]:", '[' + given + ']')
    given = base64.b64decode( given)
    # print( "given after base64 decode", given)
    mlen = int.from_bytes( given[:4], 'big')
    zm = given[4:]
    # print( "mlen:", mlen)
    # print( "zm:", zm)
    given = zlib.decompress( zm)
    # print( "given after decompress", given)
    return given

def send( r, message):
    zm = zlib.compress(message)
    mlen = len(zm)
    r.sendline( base64.b64encode(mlen.to_bytes(4, 'little') + zm).decode())
    # print( "sending::", '>>>', base64.b64encode(mlen.to_bytes(4, 'little') + zm).decode(), '<<<')

def recv_AB( r):
    given = recv( r)

    A = int.from_bytes( given[0:4], 'big')
    B = int.from_bytes( given[5:9], 'big')

    return A, B

def get_AB( secret, guess):
    A = sum(1 for s, g in zip(secret, guess) if s == g)
    B = sum(1 for g in guess if g in secret) - A
    return A, B

if __name__ == "__main__":
    if len(sys.argv) > 1:
        ## for remote access
        r = remote('up.zoolab.org', 10155)
        solve_pow(r)
    else:
        ## for local testing
        r = process( LOCAL_VERSION, shell=False)

    # print( "list len:", len(ALL_NUMBERS_LIST))
    # print('*** Implement your solver here ...')

    while ALL_NUMBERS_LIST:
        # get banner
        print( recv( r).decode())
        # header 
        print( recv( r).decode())

        # Pick the first available guess
        guess = ALL_NUMBERS_LIST[0]
        
        send( r, str(guess).encode())
        print( "guess:", guess)
        A, B = recv_AB( r)
        print( "reply A:", A, "B:", B)

        if A == 4:
            print(f"Correct! The number is", guess)
            break

        # Filter possible numbers based on feedback
        ALL_NUMBERS_LIST = [num for num in ALL_NUMBERS_LIST if get_AB(num, guess) == (A, B)]

    # get banner
    print( recv( r).decode())
    # r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
