from math import ceil
from pwn import *
import subprocess
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
capstone = Cs(CS_ARCH_X86, CS_MODE_64)
context.arch = "amd64"
EOL = "\n"

calling_convention = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
registers = ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "rsp"]

def function_wrapper(func):
	def parse(*_args, **kwargs):
		_args, args = _args[:-1], _args[-1]
		args, labels = parse_args(args)
		shellcode = kwargs.pop("pre", "")
		post = kwargs.pop("post", "")

		# Save all registers because you don't know which one will be lost by the function
		for reg in registers:
			shellcode += f"""
			push {reg}
			"""
		shellcode += f"""
		mov rbp, rsp
		and rsp, 0xffffffffffffff00
		// Align to 0x8 ?? WTF 
		sub rsp, 0x8
		"""
		# I can not use len(asm()) at the end because the shellcode may rely on a label
		offset = len(asm(shellcode))
		for value, reg in list(zip(args, calling_convention))[::-1]: # inverted to keep rdi in printf last
			if not type(value) is str:
				shellcode += f"""
				mov {reg}, {value}
				"""
				offset += len(asm("mov rax, 0"))
			# Attento che i registri saranno già riempiti, quindi scegli bene il tuo ordine
			elif value in registers:
				shellcode += f"""
				mov {reg}, {value}
				"""
				offset += len(asm("mov rax, rbx"))
			else:
				shellcode += f"""
				lea {reg}, {value}
				"""
				offset += len(asm("lea rax, [rip + 0]"))
		shellcode += func(*_args, offset)
		shellcode += """
		mov rsp, rbp
		"""
		for reg in registers[::-1]:
			shellcode += f"""
			pop {reg}
			"""
		if len(labels):
			shellcode += """
			jmp end
			"""
			shellcode += "\n".join(labels)
			shellcode += """
			end:
			"""
		shellcode += post
		return shellcode
	return parse

def parse_args(args):
	ret = []
	labels = []
	for arg in args:
		if type(arg) is bytes:
			arg = str(arg)[1:] # remove the b
			arg = f'"{arg[1:-1]}"'
		if type(arg) is str and arg not in registers:
			if arg[0] != "'":
				arg = f'"{arg}"' # servono virgolette
			name = cyclic(len(labels) + 1).decode()
			labels.append(f"{name}: .string {arg}")
			arg = f"[rip + {name}]"
		ret.append(arg)
	return ret, labels

class Patchelf:
	def __init__(self, FILE):
		self.elf = ELF(FILE)
		for section in self.elf.sections:
			if section.name == ".rodata":
				break
		else:
			raise Exception("Can't find .rodata !")
		self.section = section.data()
		self.counter = section.header.sh_addr + section.header.sh_size
		self.DUMP = "/tmp/objdata"
		self.data = self.elf.data
		
		self.need_restore = False

		self.uses_libc = False
		self.libc_functions = {}

		
	def save(self, destionation=None):
		# Set at the end to avoid corrupting other patches
		if self.need_restore:
			mprotect = f"""push rdi
			push rsi
			push rdx
			push rax
			
			// set rdi = text page
			call label
			label:
			pop rdi
			mov rsi, rdi
			and rsi, 0xffff
			sub rdi, rsi
			
			// set rsi = len
			mov rsi,  {0x3000} 
			
			// set rdx = RWX 
			mov rdx, 0x7
			
			// set rax = mprotect
			mov rax, 0xa
			
			syscall
			
			// restore registers
			pop rax
			pop rdx
			pop rsi
			pop rdi
			"""
			self.restoring_shellcode(self.elf.entry, mprotect)

		#if self.uses_libc and self.elf.relro is None:
		#	address = list(self.elf.plt.values())[-1]
		#	# I'm woried that calling a random function with no arguments may break something
		#	load_got = self.shellcode_call(address, [])

		if destionation is None:
			destionation = f"{self.elf.path}_patched"
		with open(destionation, "wb") as fd:
			fd.write(self.data)
		with open(self.DUMP, "wb") as fd:
			fd.write(self.section + b"\x90") # Nop per non lasciare null bytes
		subprocess.run(["objcopy", "--update-section", f".rodata={self.DUMP}", destionation, destionation])

	def restoring_shellcode(self, address, shellcode):
		self.need_restore = True
		shellcode += f"""jmp {self.counter}
		"""
		shellcode = asm(shellcode, vma=address)
		len_shellcode = len(shellcode)
		len_shellcode = 4 * ceil(len_shellcode/4)
		backup = self.data[address : address + len_shellcode]
		self.data = self.data[:address] + shellcode + self.data[address + len(shellcode):]

		shellcode = ""
		len_mov = len(asm("mov dword ptr[rip - 0x10], 0x10"))
		for i in range(0, len(backup), 4):
			# Can we let vma handle these offsets too ? Like a 
			shellcode += f"mov dword ptr[rip + {(address + i)} - {(self.counter + len_mov*(i//4+1))}], {u32(backup[i:i+4])}\n"
		shellcode += f"""jmp {address}"""
		log.debug(shellcode)
		shellcode = asm(shellcode, vma=self.counter)
		self.section += shellcode
		self.counter += len(shellcode)
		
	def place_shellcode(self, address, shellcode):
		jump = asm(f"jmp {self.counter}", vma=address)
		backup = self.overwrite_jump(address, jump)
		shellcode = asm(shellcode, vma=self.counter)
		self.counter += len(shellcode)
		for inst in capstone.disasm(backup, address):
			# Warning this is not enough if we are loading a variable in a register !
			# Use restore in that case !
			if inst.mnemonic in ["call", "jmp"]:
				inst = next(capstone.disasm(asm(" ".join([inst.mnemonic, inst.op_str]), vma=self.counter), self.counter))
				log.debug(f"inst changed to {inst}")
			shellcode += inst.bytes
			self.counter += len(inst.bytes)
		self.section += shellcode + asm(f"jmp {address + len(backup)}", vma=self.counter)
		self.counter += len(jump)

	def overwrite_jump(self, address, data):
		backup = b""
		disasm = capstone.disasm(self.data[address:], address)
		while len(backup) < len(data):
			next_inst = next(disasm)
			log.debug(next_inst)
			backup += next_inst.bytes	
		self.data = self.data[:address] + data + self.data[address+len(data):]
		return backup

	@function_wrapper
	def shellcode_call(self, address, offset): # offset dovuto al setup dei registri
		# all registers are protected by the function call
		shellcode = f"""
		call {address}
		"""
		return shellcode

	# RAX will be lost. Save it yourself
	def setup_libc(self, function: str) -> int: # offset dovuto al setup dei registri
		self.uses_libc = True
		if function in self.libc_functions:
			return self.libc_functions[function]

		address = self.counter
		got_fun, got_address = list(self.elf.got.items())[-1]
		offset_libc = self.elf.libc.symbols[got_fun]
		# all registers are protected by the function call
		shellcode = asm(f"""
		mov rax, qword ptr [rip + {got_address - (self.counter + len(asm("mov rax, qword ptr [rip + 0]")))}]
		add rax, {self.elf.libc.symbols[function] - offset_libc}
		call rax
		ret
		""")
		self.section += shellcode
		self.counter += len(shellcode)
		self.libc_functions[function] = address
		return address

	#https://stackoverflow.com/questions/27095286/using-scanf-with-x86-64-gas-assembly
	def log(self, address, msg: str, args: list, /, **kwargs):
		restoring = kwargs.pop("restoring", False)
		fun_address = self.setup_libc("printf")
		shellcode = self.shellcode_call(fun_address, [msg] + args, **kwargs)
		if restoring:
			self.restoring_shellcode(address, shellcode)
		else:
			self.place_shellcode(address, shellcode)

# TODO access global variable from relative address
# TODO set printf in its own region and reuse it in multiple logs
# TODO offri la possibilità di generare shellcodes su misura
# TODO scrivi in due parti per ricostruire il codice originale dopo aver eseguito lo shellcode e poi ricaricare la jump 
# TODO espandere la parte precedente per caricare gli shellcode solo dopo essere arrivati ad un certo punto del programma (per zone packate)