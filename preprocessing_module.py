#!/usr/bin/python
########################################################################################################## 
#               																				         #
#             Copyright 2016 Sergio Pastrana (spastran [at] inf [dot] uc3m [dot] es) 					 #
#               																				         #
# This script implements the preprocessing module of AVRAND to prevent code reuse attacks in AVR devices #
#               																				         #
# More info at www.seg.inf.uc3m.es/~spastran/avrand 													 #	
#               																				         #
#               																				         #
##########################################################################################################

import subprocess
import os
import serial
import time
import sys
from math import ceil,floor
from shutil import move
import argparse
import hexdump
import tempfile
from intelhex import IntelHex

PAGE_SIZE=128
branch_instructions=['rjmp', 'jmp','rcall','call','cpse','sbrc','sbrs','sbic','sbis','brbs','brbc','breq','brne','brcs','brcc','brsh','brlo','brmi','brpl','brge','brlt','brhs','brhc','brts','brtc','brvs','brvc','brie','brid'];
parser = argparse.ArgumentParser(description="This program implements the preprocessing module of AVRAND. It takes an HEX from a program and transforms it in such a way that it can be laterly randomized by the runtime module. See www.seg.inf.uc3m.es/~spastran/avrand for more details",
	formatter_class=argparse.ArgumentDefaultsHelpFormatter);
pointers=[];
fourByteOpcodes=[];
nonPartitionableInstructions=[];
offsetDataInSRAM=0;

#parser.add_argument("command", help="The full command and arguments you want to inject/execute (between quotes)");
parser.add_argument("-program", help="The name of the program", default="sample", dest="program_name");
parser.add_argument("-bin", help="Directory where binaries are stored", default="ArduinoProject/bin/sample/yun/",dest="bin_dir");
parser.add_argument("-src", help="Directory where source files are stored", default="ArduinoProject/src/sample/",dest="src_dir");
parser._optionals.title="Optional arguments"

args=parser.parse_args();


bin_dir=args.bin_dir;
src_dir=args.src_dir;
program_name=args.program_name;

	

# Uses dissasembler to get the pointers from jumps, calls (both absolute and relative) and conditional branches
# by looking at the comments generated in the dissasembly code by avr-objdump, i.e. after the colon. It also
# gets the pointers stored directly in registers when using callee-saved prologues functions.
def getListOfPointers():
	global pointers;
	dissasembly=subprocess.Popen (["avr-objdump", "-d", bin_dir+program_name+".elf"],stdout=subprocess.PIPE);
	line = dissasembly.stdout.readline();
	while line != '':
		#print line,
		if ";" in line: 
			if ("0x" in line.split(";")[1]):
				offset=line.split(":")[0].split()[0];
				destination=line.split(";")[1].split()[0];
				operation=line.split("\t")[2];
				opcode=line.split("\t")[1].strip();
				if ("0x"+offset)!=destination and (not (operation=='rcall' and ('.+0' in line))):
					if any(operation in s for s in branch_instructions):
						pointers.append("0x"+offset+":0x"+offset+":"+operation+":"+destination+":"+opcode);
				if "__prologue_saves__" in line:
					offset=hex(int(offset,16)-4);
					destination=hex(int(offset,16)+8);
					operation="prologues";
					opcode="00 00";
					pointers.append(offset+":"+offset+":"+operation+":"+destination+":"+opcode);
		line = dissasembly.stdout.readline();

# Get the list of pointers to functions that initiliaze global variables (ctors). These pointers are stored 
# between two specific sections of the dissassembly code, i.e. the _ctors_start and _ctors_end.
def getCtors():
	global pointers;
	dissasembly=subprocess.Popen (["avr-objdump", "-d", bin_dir+program_name+".elf"],stdout=subprocess.PIPE);
	line = dissasembly.stdout.readline();
	while not("<__ctors_start>" in line): 
		line = dissasembly.stdout.readline();
	line=dissasembly.stdout.readline();
	while not("<__ctors_end>" in line):
		if (line.strip()!=''):
			pointers.append("0x"+line.split(":")[0].strip()+":0x"+line.split(":")[0].strip()+":global_ctors:0x"+line.split("\t")[1].split()[0]+line.split("\t")[1].split()[1]+":00 00");
		line = dissasembly.stdout.readline();
	line=dissasembly.stdout.readline();
	pointers.append("0x"+line.split(":")[0].strip()+":0x"+line.split(":")[0].strip()+":global_ctors:0x"+line.split("\t")[1].split()[0]+line.split("\t")[1].split()[1]+":00 00");

#Gets the list of instructions having four bytes in their opcode, so as to avoid splitting them when inserting the JMP that link pages.
def getFourBytesOpcodes():
	global fourByteOpcodes;
	dissasembly=subprocess.Popen (["avr-objdump", "-d", bin_dir+program_name+".elf"],stdout=subprocess.PIPE);
	line = dissasembly.stdout.readline();
	while line != '':
		if line.strip()!='' and len(line.split("\t"))>2:
			offset=line.split(":")[0].split()[0];
			operation=line.split("\t")[2];
			opcode=line.split("\t")[1].strip();
			if len(opcode.split(" "))==4:
				fourByteOpcodes.append("0x"+offset+":"+offset+":"+operation+":"+opcode);
		line = dissasembly.stdout.readline();

def getNonPartitionableInstructions():
	global fourByteOpcodes;
	dissasembly=subprocess.Popen (["avr-objdump", "-d", bin_dir+program_name+".elf"],stdout=subprocess.PIPE);
	line = dissasembly.stdout.readline();
	while line != '':
		if line.strip()!='' and len(line.split("\t"))>2:
			offset=line.split(":")[0].split()[0];
			operation=line.split("\t")[2];
			opcode=line.split("\t")[1].strip();
			if "sbr" in operation or "cpse" in operation or "sbic" in operation or "sbis" in operation:
				nonPartitionableInstructions.append("0x"+offset+":"+offset+":"+operation+":"+opcode);
		line = dissasembly.stdout.readline();

# Gets the initial pointer to the .data section that must be copied from the flash to the SRAM memory.
# It also adds the pointer where the 'ldi' instructions are in the original code.
def getInitDataInSRAM():
	global offsetDataInSRAM;
	dissasembly=subprocess.Popen (["avr-objdump", "-d", bin_dir+program_name+".elf"],stdout=subprocess.PIPE);
	line = dissasembly.stdout.readline();
	while not("<__do_copy_data>" in line): 
		line = dissasembly.stdout.readline();
	line=dissasembly.stdout.readline();
	line=dissasembly.stdout.readline();
	line=dissasembly.stdout.readline();
	line=dissasembly.stdout.readline();
	low=line.split(",")[1].split()[0];
	offset=line.split(":")[0].split()[0];

	line=dissasembly.stdout.readline();
	high=line.split(",")[1].split()[0];
	operation='ldi_data_offset';
	opcode='00 00';
	destination="0x"+high.split("0x")[1]+low.split("0x")[1];
	pointers.append("0x"+offset+":0x"+offset+":"+operation+":"+destination+":"+opcode);
	offsetDataInSRAM=int("0x"+high.split("0x")[1]+low.split("0x")[1],16);

# Get the virtual pointers that are being copied in the SRAM, and which can be viewed by using the -D option of
# avr-objdump command, below ZTV tags.
def getVtablePointers():
	global pointers;
	dissasembly=subprocess.Popen (["avr-objdump", "-D", bin_dir+program_name+".elf"],stdout=subprocess.PIPE);
	line = dissasembly.stdout.readline();

	while True:
		if "ZTV" in line: 
			num=getNumOfVpointers(line.split("<")[1].split(">")[0]);			
			line = dissasembly.stdout.readline();
			line = dissasembly.stdout.readline();# 00
			line = dissasembly.stdout.readline();# 00
			i=2;
			while i < int(num):
				pointers.append("0x"+line.split(":")[0].strip()+":0x"+line.split(":")[0].strip()+":vpointer:0x"+line.split("\t")[1].split()[0]+line.split("\t")[1].split()[1]+":00 00");
				i+=1;
				line = dissasembly.stdout.readline();
		elif (".text" in line):
			break;
		else:
			line = dissasembly.stdout.readline();

# Uses the output of the gcc option -fdump-class-hierarchy to get the list of vpointers for a given virtual table
def getNumOfVpointers(vtable):
	file=open(bin_dir+program_name+".ino.002t.class");
	for line in file:
		if (vtable in line) and ('entries' in line):
			#Stream::_ZTV6Stream: 8u entries
			num=line.split(":")[3].split()[0][0:1];
			return num;

# Iterates the list of pointers and adds the corresponding increment depending on the type of operation that is
# going to be modified; i.e., a RJMP and RCALL adds 2 more bytes, which is the difference between absolute and relative
# versions of CALL and JMP, whereas the conditional branches add 8 more bytes due to the insertion of two additional
# JMP instructions after each BR
def addOffsets():
	global pointers;
	for p in pointers:
		if 'rjmp' in p or 'rcall' in p:
			offset=int (p.split(':')[1],16);
			original=p.split(':')[0];
			addToOffsets(p.split(':')[1],2,False);
			for i,fbop in enumerate(fourByteOpcodes):
				pOffset=int(fbop.split(':')[1],16);
				if (pOffset>offset):
					fourByteOpcodes.insert(i,original+":"+hex(offset)+":newJMP:00 00 00 00");
					break;
		elif 'br' in p.split(':')[2]:
			offset=int (p.split(':')[1],16);
			addToOffsets(p.split(':')[1],6,False);
			
# This function shifts the code when a new opcode must be inserted. It adds a given increment to all 
# the pointers (both their offsets and their destinations) that are below the given offset where the 
# opcode is being inserted.
def addToOffsets(offset,increment,considerEqual):
	global offsetDataInSRAM;
	#print "Inserting ",increment," in ",offset;
	for i,p in enumerate(pointers):
		pOriginal=p.split(':')[0];
		pOffset=int(p.split(':')[1],16);
		pOperation=p.split(':')[2];
		opcode=p.split(':')[4];
		pDestination=int(p.split(':')[3],16);
		newOff=hex(pOffset);
		newDest=hex(pDestination);
		if pOperation!='vpointer' and pOperation != 'global_ctors':
			if  pOffset>int(offset,16) or (considerEqual and pOffset==int(offset,16)):
				pOffset+=increment;
				newOff=hex(pOffset);
			if pDestination>int(offset,16) or (considerEqual and pDestination==int(offset,16)):
				pDestination+=increment;
				newDest=hex(pDestination);
		else:
			ad=p.split(":")[3].split("0x")[1];
			while (len(ad)<4):
				ad='0'+ad;
			d1="0x"+ad[0:2];
			d2="0x"+ad[2:4];
			destAddress=pc2address(int(d2,16),int(d1,16));
			addr=int("0x"+h(destAddress)+l(destAddress),16);
			if addr>int(offset,16)  or (considerEqual and addr==int(offset,16)):
				addr+=increment;
				#if p.split(":")[1]=="0x800221":
				#	print "Updated destination to: "+hex(addr),
				ad=hex(addr).split("0x")[1];
				while (len(ad)<4):
					ad='0'+ad;
				pc=address2pc(int(ad[0:2],16),int(ad[2:4],16));
				newDest="0x"+l(pc)+h(pc);
				#if p.split(":")[1]=="0x800221":
				#	print "NewDest:", newDest;
		pointers[i]=pOriginal+":"+newOff+":"+pOperation+":"+newDest+":"+opcode;
	for j,p in enumerate(fourByteOpcodes):
		pOriginal=p.split(':')[0];
		pOffset=int(p.split(':')[1],16);
		pOperation=p.split(':')[2];
		opcode=p.split(':')[3];
		newOff=hex(pOffset);
		if  pOffset>int(offset,16) or (considerEqual and pOffset==int(offset,16)):
			pOffset+=increment;
			newOff=hex(pOffset);
		fourByteOpcodes[j]=pOriginal+":"+newOff+":"+pOperation+":"+opcode;
	for j,p in enumerate(nonPartitionableInstructions):
		pOriginal=p.split(':')[0];
		pOffset=int(p.split(':')[1],16);
		pOperation=p.split(':')[2];
		opcode=p.split(':')[3];
		newOff=hex(pOffset);
		if  pOffset>int(offset,16) or (considerEqual and pOffset==int(offset,16)):
			pOffset+=increment;
			newOff=hex(pOffset);
		nonPartitionableInstructions[j]=pOriginal+":"+newOff+":"+pOperation+":"+opcode;
	offsetDataInSRAM+=increment;


# Iterates trough the list of pointers and generates a new, modified Intel hex file
def generateNewHex():
	tmp=open(bin_dir+program_name+"_modified.hex","w+");
	ih=IntelHex(bin_dir+program_name+".hex");
	binary=ih.tobinarray();
	for p in pointers:
		if 'rjmp' in p:
			offset=int(p.split(":")[1],16);
			destination=p.split(":")[3];
			binary.pop(offset);
			binary.pop(offset);
			insertOpcodeJMP(destination,offset,binary);
		elif 'jmp' in p:
			offset=int(p.split(":")[1],16);
			destination=p.split(":")[3];
			binary.pop(offset);
			binary.pop(offset); 
			binary.pop(offset);
			binary.pop(offset);
			insertOpcodeJMP(destination,offset,binary);
		elif 'rcall' in p:
			offset=int(p.split(":")[1],16);
			destination=p.split(":")[3];
			binary.pop(offset);
			binary.pop(offset);
			insertOpcodeCALL(destination,offset,binary);
		elif 'call' in p:
			offset=int(p.split(":")[1],16);
			destination=p.split(":")[3];
			binary.pop(offset);
			binary.pop(offset);
			binary.pop(offset);
			binary.pop(offset);
			insertOpcodeCALL(destination,offset,binary);
		elif 'br' in p:
			offset=int(p.split(":")[1],16);
			destination=p.split(":")[3];
			opcode=p.split(":")[4];
			binary.pop(offset);
			binary.pop(offset);
			insertOpcodeBR(destination,offset,binary,opcode);
		elif 'nop' in p:
			offset=int(p.split(":")[1],16);
			binary.insert(offset,0x00);
			binary.insert(offset+1,0x00);
		elif 'jump_link' in p:
			offset=int(p.split(":")[1],16);
			destination=p.split(":")[3];
			insertOpcodeJMP(destination,offset,binary);
		elif 'global_ctors' in p:
			offset=int(p.split(":")[1],16);
			destination=p.split(":")[3];
			binary.pop(offset);
			binary.pop(offset);
			insertOpcodeGLOBAL_CTORS(destination,offset,binary);
		elif 'vpointer' in p:
			offset=int(p.split(":")[1],16)-0x800000-0x100+offsetDataInSRAM;
			destination=p.split(":")[3];
			binary.pop(offset);
			binary.pop(offset);
			insertOpcodeVPointers(destination,offset,binary);
		elif 'ldi_data_offset' in p:
			offset=int(p.split(":")[1],16);
			destination=p.split(":")[3];
			binary.pop(offset);
			binary.pop(offset);
			binary.pop(offset);
			binary.pop(offset);
			insertOpcodeLDI_destination(destination,offset,binary);
		elif 'prologues' in p:
			offset=int(p.split(":")[1],16);
			destination=p.split(":")[3];
			ad=destination.split("0x")[1];
			while (len(ad)<4):
				ad='0'+ad;
			pc=address2pc(int(ad[0:2],16),int(ad[2:4],16));
			destination="0x"+h(pc)+l(pc);
			binary.pop(offset);
			binary.pop(offset);
			binary.pop(offset);
			binary.pop(offset);
			insertOpcodeLDI_destination(destination,offset,binary);
	ih.frombytes(binary);
	ih.write_hex_file(tmp);

# Inserts into the binary the opcode that loads a destination address in the R30 and R31 registers.
# Useful to update the pointer to the .data section and in callee-saved prologues functions.
def insertOpcodeLDI_destination(destination,offset,binary):
	ad=destination.split("0x")[1];
	while (len(ad)<4):
		ad='0'+ad;
	d1=ad[0];
	d2=ad[1];
	d3=ad[2];
	d4=ad[3];
	binary.insert(offset,int("0xe"+d4,16));
	binary.insert(offset+1,int("0xe"+d3,16));
	binary.insert(offset+2,int("0xf"+d2,16));
	binary.insert(offset+3,int("0xe"+d1,16));

# Inserts into the given offset of the binary the opcode for the vpointers, in the corresponding offset of the vtable
def insertOpcodeVPointers(destination,offset,binary):
	ad=destination.split("0x")[1];
	while (len(ad)<4):
		ad='0'+ad;
	binary.insert(offset,int("0x"+ad[0:2],16));
	binary.insert(offset+1,int("0x"+ad[2:4],16));

# Inserts into the given offset of the binary the opcode of the global_ctors pointers.
def insertOpcodeGLOBAL_CTORS(destination,offset,binary):
	ad=destination.split("0x")[1];
	while (len(ad)<4):
		ad='0'+ad;
	binary.insert(offset,int("0x"+ad[0:2],16));
	binary.insert(offset+1,int("0x"+ad[2:4],16));

# Inserts into the given offset of the binary the opcode for a call instruction pointing at a given destination
def insertOpcodeCALL(destination,offset,binary):
	binary.insert(offset,0x0e);
	binary.insert(offset+1,0x94);
	ad=destination.split("0x")[1];
	while (len(ad)<4):
		ad='0'+ad;
	pc=address2pc(int(ad[0:2],16),int(ad[2:4],16));
	binary.insert(offset+2,int("0x"+l(pc),16));
	binary.insert(offset+3,int("0x"+h(pc),16));

# Inserts into the given offset of the binary the opcode for a JMP instruction pointing at a given destination
def insertOpcodeJMP(destination,offset,binary):
	binary.insert(offset,0x0c);
	binary.insert(offset+1,0x94);
	ad=destination.split("0x")[1];
	while (len(ad)<4):
		ad='0'+ad;
	pc=address2pc(int(ad[0:2],16),int(ad[2:4],16));
	#print "Inserting JMP offset:",hex(offset),"destination:",destination,"pc:",pc;
	binary.insert(offset+2,int("0x"+l(pc),16));
	binary.insert(offset+3,int("0x"+h(pc),16));

# Inserts into the given offset of the binary the opcode por a RJMP +4
def insertOpcodeRJMP4 (offset,binary):
	binary.insert(offset,0x02);
	binary.insert(offset+1,0xc0);

# Inserts into the given offset of the binary the opcode for a conditional branch. 
# It then inserts two JMP instrucionts. First, 
# a JMP to the code that where right after the original conditional jump, and second a JMP to the destination
# address of the conditional branch. The function thus sets the conditional jump to always point 
# current address plus 4 (i.e., to the second JMP)
def insertOpcodeBR(destination,offset,binary,opcode):
	hexOpcode=int(opcode.split()[1]+opcode.split()[0],16);
	newOpcode=modifyBRopcode(hexOpcode);
	binary.insert(offset,int(newOpcode.split()[0],16));
	binary.insert(offset+1,int(newOpcode.split()[1],16));
	#insertOpcodeJMP(hex(offset+0xa),offset+2,binary);
	insertOpcodeRJMP4(offset+2,binary);
	#insertOpcodeJMP(destination,offset+6,binary);
	insertOpcodeJMP(destination,offset+4,binary);

# Modifies the opcode of a branch to always jump to the current addres + 2
def modifyBRopcode (opcode):
	maskDelete=0xFC07;
	delete=opcode & maskDelete;
	maskAdd=0x0008;
	newOpcode=delete | maskAdd;
	ad=hex(newOpcode).split("0x")[1];
	return ad[2:4]+" "+ad[0:2];


# Inserts a 'nop' (2 bytes) at the given offset
def addNOPtoPointers(offset):
	addToOffsets(hex(offset),2,True);
	for i,p in enumerate(pointers):
		pOffset=int(p.split(':')[1],16);
		if (pOffset>offset):
			pointers.insert(i,hex(offset)+":"+hex(offset)+":nop:0x0000:00 00");
			break;

# Inserts a JMP into the given offset to the following position, in order to link consecutive pages
def addJMPLink(offset):
	addToOffsets(hex(offset),4,True);
	for i,p in enumerate(pointers):
		pOffset=int(p.split(':')[1],16);
		if (pOffset>offset):
			destination=offset+4;
			pointers.insert(i,hex(offset)+":"+hex(offset)+":jump_link:"+hex(destination)+":00 00");
			break;

# Auxiliary function used for debugging purposes (Not used anymore, kept for future modifications)
def checkNew():
	subprocess.Popen(["avr-objcopy","-I", "ihex", "-O", "elf32-avr", "--rename-section",".sec1=.text", bin_dir+program_name+"_modified.hex", bin_dir+"myNewELF.elf"]);
	print "Creating myNewELF.elf ...";
	time.sleep(2);
	dissasembly=subprocess.Popen (["avr-objdump", "-D", bin_dir+"myNewELF.elf"],stdout=subprocess.PIPE);
	line = dissasembly.stdout.readline();
	myPointers=[];
	while line != '':
		if ";" in line: 
			if ("0x" in line.split(";")[1]):
				offset=line.split(":")[0].split()[0];
				destination=line.split(";")[1].split()[0];
				operation=line.split("\t")[2];
				opcode=line.split("\t")[1].strip();
				if any(operation in s for s in branch_instructions):
					myPointers.append("0x"+offset+":0x"+offset+":"+operation+":"+destination+":"+opcode);
		line=dissasembly.stdout.readline();
	for p in myPointers:
		if 'br' in p:
			offset=int(p.split(":")[1],16);
			for i in range(2,12,2):
				if (offset+i)%PAGE_SIZE==0:
					page,of=getPageAndOffset(offset);
					print page, "->",hex(offset),"(+"+str(i)+")";
					print p;
		
# Links pages with absloute JMP instructions. 
# Adds padding if needed to avoid conditional branches relying on inmediate JMPS being divided between pages. 
def checkPageLimits():
	num_pages= int(floor(offsetDataInSRAM/PAGE_SIZE));
	#print "Num pages:",num_pages;
	i=PAGE_SIZE*5;
	while i < num_pages*PAGE_SIZE:
		dif=checkCodeInLimit(i);
		if dif < 12 and dif>4:
			init=i-dif;
			for j in range (init,i-4,2):
				if (isInNonPartitionableInstructions(j)):
					addNOPtoPointers(j-2);
				else:
					addNOPtoPointers(j);
		dif3=checkPrologues(i);
		if dif3 < 12 and dif3>0:
			init=i-dif3-2;
			for j in range (init,i-4,2):
				if (isInNonPartitionableInstructions(j)):
					addNOPtoPointers(j-2);
				else:
					addNOPtoPointers(j);
		dif2=checkFourByteOpcodes(i-4);
		if dif2==2:
			if (isInNonPartitionableInstructions(i-6)):
				addNOPtoPointers(i-8);
			else:
				addNOPtoPointers(i-6);
		if (isInNonPartitionableInstructions(i-4)):
			addNOPtoPointers(i-6);
		addJMPLink(i-4);
		i+=PAGE_SIZE;
		num_pages= int(floor(offsetDataInSRAM/PAGE_SIZE));

#Checks if the offset is between a LDI of the prologue address
def checkPrologues(offset):
	for p in pointers:
		pOffset=int(p.split(':')[1],16);
		if ('prologue' in p and (offset - pOffset) < 12 and (offset-pOffset)>0):
			return offset-pOffset;
	return -1
# Checks if the offset is between a BR+JMP+JMP instruction, which cannot be divided
def checkCodeInLimit(offset):
	for p in pointers:
		pOffset=int(p.split(':')[1],16);
		if ('br' in p and (offset - pOffset) < 12 and (offset-pOffset)>0):
			return offset-pOffset;
	return -1
# Checks if the offset is in a non-partitionable instruction (e.g. SBR) 
def isInNonPartitionableInstructions(offset):
	for p in nonPartitionableInstructions:
		pOffset=int(p.split(':')[1],16);
		if (offset==pOffset+2):
			return True;
	return False;
# Checks if the offset is between a 4 byte opcode.
def isInFourByteOpcodes(offset):
	for p in fourByteOpcodes:
		pOffset=int(p.split(':')[1],16);
		if (offset - pOffset) <= 3 and (offset-pOffset)>0:
			return True;
	return False;
def checkFourByteOpcodes(offset):
	for p in fourByteOpcodes:
		pOffset=int(p.split(':')[1],16);
		if offset - pOffset == 2:
			#print "Four bytes op in limit:",hex(offset), "DIF:",abs(offset-pOffset);
			#print p;
			return offset - pOffset;
	return -1;

offsetRelationship=[];

# Obtains the offset relationships that must be stored in the device to assist the bootloader when calculating the new offsets.
# Each pointer requires 3 bytes: 1-PAGE_OF_POINTER 2-offsetInPage_type(see function mixOffsetAndType) 3-POINTED_PAGE
def getOffsetRelationships():
	subprocess.Popen(["avr-objcopy","-I", "ihex", "-O", "elf32-avr", "--rename-section",".sec1=.text", bin_dir+program_name+"_modified.hex", bin_dir+"myNewELF.elf"]);
	print "Creating myNewELF.elf ...";
	time.sleep(2);
	dissasembly=subprocess.Popen (["avr-objdump", "-D", bin_dir+"myNewELF.elf"],stdout=subprocess.PIPE);
	line = dissasembly.stdout.readline();
	myPointers=[];
	while line != '':
		#print line,
		#if line.strip()!='' and len(line.split("\t"))>2:
		#	offset=line.split(":")[0].split()[0];
		#	if (int(offset,16)+4)%PAGE_SIZE==0:
		#		print line;
		if ";" in line: 
			if ("0x" in line.split(";")[1]):
				offset=line.split(":")[0].split()[0];
				destination=line.split(";")[1].split()[0];
				operation=line.split("\t")[2];
				opcode=line.split("\t")[1].strip();
				if any(operation in s for s in branch_instructions):
					myPointers.append("0x"+offset+":0x"+offset+":"+operation+":"+destination+":"+opcode);
		line=dissasembly.stdout.readline();
	numRJMP=0;
	numRCALL=0;
	for p in myPointers:
		offset=int(p.split(':')[1],16);
		operation=p.split(':')[2];
		destination=int(p.split(':')[3],16);
		if operation == "jmp" or operation == "call":
			page,offsetInPage=getPageAndOffset(offset);
			destPage,destOffsetInPage=getPageAndOffset(destination);
			offsetType=mixOffsetAndType(offsetInPage,0);
			#print "PageNumber:",page,"OffsetPage:",offsetInPage,"destPage:",destPage,"offsetType:",hex(offsetType),"type:",operation;
 			offsetRelationship.append(hex(page)+":"+hex(offsetType)+":"+hex(destPage));
	for p in pointers:
		offset=int(p.split(':')[1],16);
		operation=p.split(':')[2];
		destination=int(p.split(':')[3],16);
		if operation == "global_ctors" or operation=="vpointer":
			if (operation=="vpointer"):
				offset=int(p.split(":")[1],16)-0x800000-0x100+offsetDataInSRAM;
			ad=p.split(":")[3].split("0x")[1];
			while (len(ad)<4):
				ad='0'+ad;
			d1="0x"+ad[0:2];
			d2="0x"+ad[2:4];
			destAddress=pc2address(int(d2,16),int(d1,16));
			addr=int("0x"+h(destAddress)+l(destAddress),16);
			page,offsetInPage=getPageAndOffset(offset);
			destPage,destOffsetInPage=getPageAndOffset(addr);
			op=2;
			# To handle VPOINTERS that are at an odd position in the DATA section, we use the previously unused type 3
			if (operation=="vpointer" and offsetInPage%2==1):
				op=3;
			offsetType=mixOffsetAndType(offsetInPage,op);
			#offsetRelationship.append(hex(page)+":"+hex(offsetInPage)+":"+hex(destPage)+":"+hex(destOffsetInPage)+":"+hex(3));
			#print "PageNumber:",page,"OffsetPage:",offsetInPage,"destPage:",destPage,"offsetType:",hex(offsetType),"type:",operation;
			offsetRelationship.append(hex(page)+":"+hex(offsetType)+":"+hex(destPage));
		elif operation == "prologues":
			page,offsetInPage=getPageAndOffset(offset);
			destPage,destOffsetInPage=getPageAndOffset(destination);
			offsetType=mixOffsetAndType(offsetInPage,1);
			#offsetRelationship.append(hex(page)+":"+hex(offsetInPage)+":"+hex(destPage)+":"+hex(destOffsetInPage)+":"+hex(2));
			#print "PageNumber:",page,"OffsetPage:",offsetInPage,"destPage:",destPage,"offsetType:",hex(offsetType),"type:",operation;
			offsetRelationship.append(hex(page)+":"+hex(offsetType)+":"+hex(destPage));

# Since offsets are always at an even position in code section (except from VPOINTERS, which are in data section and may be at odd position)
# the maximum number of bits required to represent the offsetInPage is 6 (0-63) and thus the remainder 2 bits of the byte are used to encapsulate
# the type of pointer (i.e. 0-> JMP/CALL, 1->PROLOGUE, 2-> CTOR or EVEN_VPOINTER, 3-> ODD_VPOINTER)
def mixOffsetAndType(offset,type):
	return (offset/2) | (type<<6);

# Returns the number of page and offset within the page of the offset given as parameter
def getPageAndOffset(offset):
	page=offset/PAGE_SIZE;
	offsetInPage=offset%PAGE_SIZE;
	return page,offsetInPage;


# Provide the lowest bytes of an address (which must be formatted between '0x's)
def l(address):
	return address.split("0x")[2];

# Provide the highest bytes of an address (which must be formatted between '0x's)
def h(address):
	return address.split("0x")[1];

# Translate an absolute address into a PC address
def address2pc(a,b):
	wd = (a << 8) | b;
	dividend=wd/64;
	remainder=(wd%64)/2;
	dividend=dividend<<5;
	p=remainder & 0x003F;
	q=dividend & 0xFFE0;
	pc=p | q;
	first=(pc & 0xFF00)>>8;
	second=(pc & 0x00FF);
	#print hex(a),hex(b),"->",hex(first),hex(second);
	tf=hex(first);
	if (len(tf)==3):
		tf="0x0"+hex(first)[2:];
	ts=hex(second);
	if (len(ts)==3):
		ts="0x0"+hex(second)[2:];
	return tf+ts;

# Translates a PC address into an absolute address
def pc2address(a,b):
	wd = (a << 8) | b;
	p=wd & 0x001F;
	q=wd & 0xFFE0;
	q=q>>5;
	address=q*64+p*2;
	first=(address & 0xFF00)>>8;
	second=(address & 0x00FF);
	#print hex(a),hex(b),"->",hex(first),hex(second);
	tf=hex(first);
	if (len(tf)==3):
		tf="0x0"+hex(first)[2:];
	ts=hex(second);
	if (len(ts)==3):
		ts="0x0"+hex(second)[2:];
	return tf+ts;

# Print the list of pointers
def printPointers():
	for pointer in pointers:
		print pointer;
lastOffset=0;
def printOffsetRelationshipCStyle():
	global lastOffset;
	print"-----";
	print"-----";
	print "__attribute__ ((used,section (\".absolutePointers\"))) const uint8_t pageOffsets["+str(len(offsetRelationship)*3)+"]={",
	for i,p in enumerate(offsetRelationship):
		if (i!=len(offsetRelationship)-1):
			#print p.split(":")[0]+","+p.split(':')[1]+","+p.split(':')[2]+","+p.split(':')[3]+","+p.split(':')[4]+",",
			print p.split(":")[0]+","+p.split(':')[1]+","+p.split(':')[2]+",",
		else:
			#print p.split(":")[0]+","+p.split(':')[1]+","+p.split(':')[2]+","+p.split(':')[3]+","+p.split(':')[4],
			print p.split(":")[0]+","+p.split(':')[1]+","+p.split(':')[2],

		thisOffset=int(p.split(":")[0],16)*PAGE_SIZE+int(p.split(":")[1],16);
		if thisOffset > lastOffset:
			lastOffset=thisOffset;
	print "};";
	print "#define NUM_PAGES",int(floor(float(lastOffset)/float(PAGE_SIZE)));
	print "#define numOffsets",str(len(offsetRelationship)*3);
	print "#define lastRandomizablePage",int(floor(float(offsetDataInSRAM)/float(PAGE_SIZE)))-1;
	print"-----";
	print;
	print;
	print "IMPORTANT:\n1. The above lines (between '-----') must be copied in the bootloader C file before compiling it. It corresponds with the public metadata";
	print;
	print "2. Modify your bootloader's Makefile with the following position for '.absolutePointers': "+hex(0x7000-1-len(offsetRelationship)*3);
	createHexWithPagePositions(lastOffset);
	print "3. An HEX file with private metadata has been created in the binary folder ("+bin_dir+"). Remember to store it in the EEPROM.\nExample of usage:";
	print "\tavrdude -C [PATH_TO_AVRDUDE_CONFIG_FILE] -p atmega32u4 -P /dev/cu.usbmodem1411 -c avr109 -U eeprom:w:sample_privateData.hex:i";
	print;
	print;
	#print "uint16_t lastPage="+hex(lastOffset);
def printPagePositionsCStyle():
	i=0;
	num_pages= floor(float(lastOffset)/float(PAGE_SIZE));
	print "__attribute__ ((used,section (\".pagePositions\"))) const uint16_t pagePositions["+str(int(num_pages))+"]={",
	while i < (num_pages-1)*PAGE_SIZE:
		print hex(i)+",",
		i+=PAGE_SIZE;
	print hex(i)+"};";

def createHexWithPagePositions(lastOffset):
	tmp=open(bin_dir+program_name+"_privateData.hex","w+");
	ih=IntelHex();
	num_pages= floor(float(lastOffset)/float(PAGE_SIZE));
	initPosition=0;
	counterEPROM=initPosition;
	i=0;
	while i < num_pages*PAGE_SIZE:
		first=(i & 0xFF00)>>8;
		second=(i & 0x00FF);
		# LITTLE ENDIAN
		ih[counterEPROM]=second;
		ih[counterEPROM+1]=first;
		i+=PAGE_SIZE;
		counterEPROM+=2;
	print;
	ih.write_hex_file(tmp);

print "Obtaining control flow statements..."
getFourBytesOpcodes();
getNonPartitionableInstructions();
getListOfPointers();
getVtablePointers();
getCtors();
getInitDataInSRAM();

print "Modifying code..."
addOffsets();
checkPageLimits();
print "Generating new hex file..."
generateNewHex();

print "Getting public and private metadata..."
getOffsetRelationships();
printOffsetRelationshipCStyle();