#! /usr/bin/env python3

from pwn import *

if __name__ == "__main__":
	# the string to send
	msg = """
GET /ip HTTP/1.1
Host: ipinfo.io
User-Agent: curl/7.88.1
Accept: */*
	"""
	r = remote( 'ipinfo.io', 80)
	r.send( msg.encode())
	r.sendline( ''.encode())
	r.sendline( ''.encode())

	# r.interactive()

	# remove the big headers
	given = r.recvuntil( b'includeSubDomains\r\n\r\n')

	# print decode of the byte string
	given = r.recv()
	print( given.decode())

