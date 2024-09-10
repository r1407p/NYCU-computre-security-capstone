#!/usr/bin/env python3
import pwn
import time
import subprocess
import os
def remote(ip, port):
    p = pwn.remote(ip, port)

    result = subprocess.run(['./my_magic.out'], stdout=subprocess.PIPE, text=True)
    p.recvuntil(b'Please enter the secret:')
    p.sendline(result.stdout.encode())

    # receive all messages
    print(p.recvuntil(b'}').decode())

if __name__ == "__main__":
    remote('140.113.24.241', 30171)