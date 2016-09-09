#!/usr/bin/python

# GNU LibC symbol collection - Console
# ver1.0
# trichimtrich

from elftools.elf.elffile import ELFFile
import json, hashlib, re, sys, os
from struct import pack, unpack

collects = {}


#extract function, name symbol
#extract binsh
#extract gotplt/ebx/esi, magic1, magic2, magic3
def extract_symbol(fn):
	elffile = ELFFile(open(fn,'rb'))
	section = elffile.get_section_by_name('.dynsym')

	ar = {}
	for sym in section.iter_symbols():
		if sym.name=="" or sym.entry['st_value']==0: continue
		ar[sym.name] =sym.entry['st_value']

	#read all data
	elffile.stream.seek(0)
	data = elffile.stream.read()

	#string binsh
	off_binsh = data.find('/bin/sh')
	if off_binsh>0: ar['binsh'] = off_binsh
	
	#find magic gadget
	# intel-i386
	if elffile.get_machine_arch()=="x86": 
		if elffile.get_section_by_name('.got.plt') != None:
			ar['gotplt'] = elffile.get_section_by_name('.got.plt').header['sh_addr']
		
			#first magic gadget
			#condition: ebx = ar['gotplt'] and [esp + 0x34] = NULL -> OKE
			'''
			0x0004003B
			.text:0004003B 8B 83 44 FF FF FF                    mov     eax, ds:(environ_ptr_0 - 1AA000h)[ebx]
			.text:00040041 C7 83 20 16 00 00 00+                mov     ds:(dword_1AB620 - 1AA000h)[ebx], 0
			.text:0004004B C7 83 24 16 00 00 00+                mov     ds:(dword_1AB624 - 1AA000h)[ebx], 0
			.text:00040055 8B 00                                mov     eax, [eax]
			.text:00040057 89 44 24 08                          mov     [esp+16Ch+var_164], eax
			.text:0004005B 8D 44 24 34                          lea     eax, [esp+16Ch+var_138] ; Load Effective Address
			.text:0004005F 89 44 24 04                          mov     [esp+16Ch+var_168], eax
			.text:00040063 8D 83 24 6A FB FF                    lea     eax, (aBinSh - 1AA000h)[ebx] ; "/bin/sh"
			.text:00040069 89 04 24                             mov     [esp+16Ch+status], eax
			.text:0004006C E8 6F 5B 07 00                       call    execve          ; Call Procedure
			'''
			clgv = 0x100000000 + (ar['binsh'] - ar['gotplt'])
			magic1 = data.find(pack('<I', clgv))
			while magic1>=5 and (data[magic1]!='\x8b' or data[magic1-5]!='\xe8'): magic1 -= 1
			if magic1 > 0: ar['magic1'] = magic1
		
			#second/third magic gadget
			#condition: ebx = ar['gotplt'] and [esp + 0x8] = NULL -> OKE
			'''
			.text:00065509 8D 83 29 6A FB FF                             lea     eax, (aBinSh+5 - 1AA000h)[ebx] ; "sh"
			.text:0006550F 89 44 24 04                                   mov     [esp+5Ch+var_58], eax
			.text:00065513 8D 83 24 6A FB FF                             lea     eax, (aBinSh - 1AA000h)[ebx] ; "/bin/sh"
			.text:00065519 89 04 24                                      mov     [esp+5Ch+status], eax
			.text:0006551C E8 9F 09 05 00                                call    execl           ; Call Procedure


			.text:0012730A 8D 83 29 6A FB FF                             lea     eax, (aBinSh+5 - 1AA000h)[ebx] ; "sh"
			.text:00127310 89 44 24 04                                   mov     [esp+6Ch+var_68], eax
			.text:00127314 8D 83 24 6A FB FF                             lea     eax, (aBinSh - 1AA000h)[ebx] ; "/bin/sh"
			.text:0012731A 89 04 24                                      mov     [esp+6Ch+status], eax
			.text:0012731D E8 9E EB F8 FF                                call    execl           ; Call Procedure
			'''
			clgv = 0x100000000 + (ar['binsh'] + 5 - ar['gotplt'])
			if data.count(pack('<I', clgv))>=3:
				fist = data.find(pack('<I', clgv))

				magic2 = data.find(pack('<I', clgv), fist + 1) - 2
				if magic2 > 0: ar['magic2'] = magic2
		
				magic3 = data.find(pack('<I', clgv), magic2 + 3) - 2
				if magic3 > 0: ar['magic3'] = magic3

			print "-"*20 + "x86",
			if ar.has_key('magic1'): print "0x%x" % ar['magic1'],
			if ar.has_key('magic2'): print "0x%x" % ar['magic2'],
			if ar.has_key('magic3'): print "0x%x" % ar['magic3'],
			print

	# amd64
	elif elffile.get_machine_arch()=="x64":
		#first magic gadget
		#condition: [rsp + 0x30] = NULL -> OKE
		'''
		.text:000000000004647C 48 8B 05 25 7A 37 00                          mov     rax, cs:environ_ptr_0
		.text:0000000000046483 48 8D 3D 39 64 13 00                          lea     rdi, aBinSh     ; "/bin/sh"
		.text:000000000004648A 48 8D 74 24 30                                lea     rsi, [rsp+188h+var_158] ; Load Effective Address
		.text:000000000004648F C7 05 27 A2 37 00 00 00 00 00                 mov     cs:dword_3C06C0, 0
		.text:0000000000046499 C7 05 2D A2 37 00 00 00 00 00                 mov     cs:dword_3C06D0, 0
		.text:00000000000464A3 48 8B 10                                      mov     rdx, [rax]
		.text:00000000000464A6 E8 35 AD 07 00                                call    execve          ; Call Procedure
		'''
	
		#second magic gadget
		#condition: [rsp + 0x50] = NULL -> OKE
		'''
		.text:00000000000E5765 48 8B 05 3C 87 2D 00                          mov     rax, cs:environ_ptr_0
		.text:00000000000E576C 48 8D 74 24 50                                lea     rsi, [rsp+1B8h+var_168] ; Load Effective Address
		.text:00000000000E5771 48 8D 3D 4B 71 09 00                          lea     rdi, aBinSh     ; "/bin/sh"
		.text:00000000000E5778 48 8B 10                                      mov     rdx, [rax]
		.text:00000000000E577B E8 60 BA FD FF                                call    execve          ; Call Procedure
		'''

		#third magic gadget
		#condition: [rsp + 0x70] = NULL -> OKE
		'''
		.text:00000000000E66BD 48 8B 05 E4 77 2D 00                          mov     rax, cs:environ_ptr_0
		.text:00000000000E66C4 48 8D 74 24 70                                lea     rsi, [rsp+1D8h+var_168] ; Load Effective Address
		.text:00000000000E66C9 48 8D 3D F3 61 09 00                          lea     rdi, aBinSh     ; "/bin/sh"
		.text:00000000000E66D0 48 8B 10                                      mov     rdx, [rax]
		.text:00000000000E66D3 E8 08 AB FD FF                                call    execve    
		'''

		index = 2
		for i in range(len(data)-4):
			if ar['binsh'] == i+4 + unpack('<I', data[i:i+4])[0] and data[i-3:i] == "\x48\x8D\x3D":
				if data[i-10:i-7] == "\x48\x8b\x05": ar['magic1'] = i - 10
				if data[i+4:i+8] == "\x48\x8B\x10\xe8":
					ar['magic%d' % index] = i - 15
					index += 1

		print "-"*20 + "x64",
		if ar.has_key('magic1'): print "0x%x" % ar['magic1'],
		if ar.has_key('magic2'): print "0x%x" % ar['magic2'],
		if ar.has_key('magic3'): print "0x%x" % ar['magic3'],
		print
	
	#retn (md5, sha1, sha256, symbol array)
	return hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest(), hashlib.sha256(data).hexdigest(), elffile.get_machine_arch(), ar


#convert libc to symbol file
def libc_to_sym(sofn, symfn, name="", desc=""):
	if not os.path.exists(sofn):
		print "File %s not found" % sofn
		sys.exit(1)
	if name=="": name = sofn.split('/')[-1]
	md5, sha1, sha256, arch, sym = extract_symbol(sofn)
	json.dump({md5 : {	'name' : name,
						'hash' : {'md5' : md5, 'sha1' : sha1, 'sha256' : sha256},
						'arch' : arch,
						'desc' : desc,
						'symbol' : sym}}, open(symfn, 'wb'))
	return symfn


#combine multiple symbol files into one
def syms_to_sym(symar, symfn):
	sym = {}
	for fn in symar:
		if not os.path.exists(fn):
			print "File %s not found" % fn
			continue
		ar = json.load(open(fn, 'rb'))
		for key in ar.keys():
			if sym.has_key(key): print "Dup:", fn, key 
			else: sym[key] = ar[key]
	json.dump(sym, open(symfn, 'wb'))
	return symfn


#search libc and symbols
def search_symbol(inputs, outputs):
	hope = []
	for md5 in collects.keys():
		collect = collects[md5]
		ar = collect['symbol']
		thisisit = True
		for sym, add in inputs:
			if ar.has_key(sym) and (ar[sym]&0xfff) != (add&0xfff):
				thisisit = False
				break
		if not thisisit: continue

		print """[+] Found
	Name: {0}
	Architecture: {5}
	Hash:
		md5 = {1}
		sha1 = {2}
		sha256 = {3}
	Description: {4}
	Symbol:""".format(collect['name'], collect['hash']['md5'], collect['hash']['sha1'], collect['hash']['sha256'], collect['desc'], collect['arch'])
		symbol = []
		for sym in outputs:
			if ar.has_key(sym): 
				print "\t\t%s = 0x%x" % (sym, ar[sym])
			else:
				print "\t\t%s = not found" % sym
	return None


def help():
	print """Usage:
	+ Search symbol:
		python {0} search symbol=offset symbol=? ...

	+ Extract symbol from libc: 
		python {0} extract <libc.so file> <symbol file> [name] [description]

	+ Combine many symbol files to one:
		python {0} combine <outfile> <infile1> <infile2> ...\n""".format(sys.argv[0])
	sys.exit(1)


#console version uses data from json in libc.sym
if os.path.exists("libc.sym"): collects = json.load(open("libc.sym", "rb"))

if __name__ == "__main__":
	print "LIBc Symbol Collection, version 1.0, trichimtrich\n"
	if len(sys.argv)<2: help()

	if sys.argv[1] == "extract":
		fn = libc_to_sym(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
		if fn: print "OK -> %s" % fn
	elif sys.argv[1] == "combine":
		fn = syms_to_sym(sys.argv[3:], sys.argv[2])
		if fn: print "OK -> %s" % fn
	elif sys.argv[1] == "search":
		ar_input = []
		ar_output = []
		for arg in sys.argv[2:]:
			if arg.count('=')!=1: continue
			sym, value = arg.split('=')
			ar_output.append(sym)
			try:
				if value.isdigit(): value = int(value)
				else: value = int(value, 16)
			except: value = -1
			if value >= 0: ar_input.append((sym, value))
		if len(ar_input)>0: search_symbol(ar_input, ar_output)
	else: help()