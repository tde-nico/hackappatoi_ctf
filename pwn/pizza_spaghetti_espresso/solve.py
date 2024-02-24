#!/usr/bin/env python3

from pwn import *
import ctypes

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./pse")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

libc = ctypes.CDLL("libc.so.6")
libc.srand(libc.time(None))


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("92.246.89.201", 10001)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	choices = [b"Espresso", b"Spaghetti", b"Pizza"]

	for i in range(10):
		c = libc.rand() % 3
		r.sendlineafter(">>", choices[c])
		print(choices[c])
	
	r.interactive()


if __name__ == "__main__":
	main()
