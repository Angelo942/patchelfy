# Patchelfy

Patchelfy is a library to inject new code into an ELF without breaking it. It can be used when you can't attach to the process to alter part of the execution or simply log informations while reversing it.

The code has to be written in assembly and some methods are offered to add calls to any libc function or to access specific addresses in the binary.

## Log

The simplest use for this library is to log data during the execution.

You can write as many shellcodes as you want on the same address, but you just have to keep in mind that they will be called from the last to the fist you set and the memory will be restored between each of them.

```py
from patchelfy import Patchelf
p = Patchelf("./binary")
# Warning the \n must be escaped
p.log(0x1651, "the function returned %ld\\n", ["rax"])
p.log(0x1651, "I'm at address: 0x%lx\\n", [0x1651])
p.log(0x1651, "This is a log\\n", [])
#p.save("./binary_patched")
# If left empty the name for the new binary will be <name>_patched
p.save()
```

output:
```
$ ./binary_patched
This is a log
I'm at address: 0x1651
the function returned 0x7f41f656a000
````

### Access variables on stack

To access variables on the stack, or in another stackframe, you can load them into a register with `pre`. Remember to save the original value and restore it after.

```py
from patchelfy import Patchelf
p = Patchelf("./binary")

shellcode = """
push rbp
push rbx
mov rbp, qword ptr [rbp]
mov ebx, dword ptr [rbp - 0x4]
"""

p.log(0x154c, "[process: %d] returned %ld\\n", ["rbx", "rax"], pre=shellcode, post="pop rbx\npop rbp")
p.save()
```

## Place shellcodes

You can insert your own shellcodes inside the binary and reffer to functions in the binary by their relative address

```py
from patchelfy import Patchelf
p = Patchelf("./binary")

# Skip a portion of code
shellcode = """
jmp 0x1537
"""

p.place_shellcode(0x1526, shellcode)
p.save()
```

### Calling a function

If you have to call a function in your shellcode you can use the wrapper `Patchelf.shellcode_call` to save all registers and parse your arguments.
If the function you want to call is in the libc you can get a relative address to it with `Patchelf.setup_libc` to build your shellcode. 
```py
from patchelfy import Patchelf
p = Patchelf("./binary")

system_address = p.setup_libc("memcpy")
ptable = list(range(0x100))
shellcode = p.shellcode_call(system_address, [0x205153, ptable, 0x100])
p.place_shellcode(0x1526, shellcode)
p.save()
```

## Edge cases

To place your shellcode we overwrite 6 bytes of the binary. It is not a problem except if the program has to jump right in that area. Try not to place it there, but if you REALY have to you can use restoring_shellcode that restore the memory once executed. Unfortunately there is nothing I can do if you jump into that area before running your shellcode.

```py
from patchelfy import Patchelf
p = Patchelf("./binary")

# overwrite return value with True
shellcode = """
xor rax, rax
inc rax
"""

p.restoring_shellcode(0x15a3, shellcode)
# If you are in a loop and want your shellcode to be executed each time you need a point to set again your shellcode. This will be developed in a future version
#p.restoring_shellcode(0x15a3, shellcode, loop = 0x15bb)
p.save()
```

If you need it for a log, use the argument `p.log(..., restoring=True)`

## Installation

stable
```
pip3 install patchelfy
```

## Limitations

- Can not yet patch a section that will be unpacked at runtime. I will look into a setup to handle it. 
- Setup_libc requires the binary to be relro or at least the last function in the got table to be loaded when called. You can inject a restoring_shellcode on entry to the last function of the plt or disable ASLR, load the absolute address in a register and call that register.
- You can only write 2MB of shellcode... Do you really have a case where it isn't enough ? 