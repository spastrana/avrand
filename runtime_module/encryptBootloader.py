#!/usr/bin/python

########################################################################################################## 
#               																				         #
#             Copyright 2016 Sergio Pastrana (spastran [at] inf [dot] uc3m [dot] es) 					 #
#               																				         #
# This script takes the original HEX with the bootloader and encrypts it. 								 #
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
bootloaderName="myBootLoader"
bootloader_dir="./"
initAddr=0x7100;
initDecryptor=0x7E00;

parser = argparse.ArgumentParser(description="This program encrypts the original HEX from an specific address, without encrypting the decryption routine",formatter_class=argparse.ArgumentDefaultsHelpFormatter);

parser.add_argument("-name", help="The name of the bootloader", default="myBootLoader", dest="bootloaderName");
parser.add_argument("-initAddr", help="Initial address (in hexadecimal) of the code that must be encrypted", default="0x7100", dest="initAddr");
parser.add_argument("-initDecryptor", help="Address (in hexadecimal) of the decryption routine", default="0x7E00", dest="initDecryptor");
parser.add_argument("-directory", help="Name of the directory where the bootloader is (relative or absolute)", default="./", dest="bootloader_dir");

args=parser.parse_args();

bootloaderName=args.bootloaderName;
bootloader_dir=args.bootloader_dir;
initAddr=args.initAddr;
initDecryptor=args.initDecryptor;


key=[0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa]

endAddr=initDecryptor-2;

def encrypt():
	tmp=open(bootloader_dir+bootloaderName+"_encrypted.hex","w+");
	ih=IntelHex(bootloader_dir+bootloaderName+".hex");
	keyPos=0;
	dictionary=ih.todict();
	addresses=dictionary.keys();
	pages=-1;
	for b in addresses:
		#print hex(p)+":"+hex(dictionary[p]);
		if (b!="start_addr") and b>=initAddr and b<endAddr:
			#print b,hex(b);
			if (b%PAGE_SIZE)==0:
				pages=pages+1;
				keyPos=0
				print;
				print;
				print "PAGE ",pages;
			print hex(b)+":"+hex(dictionary[b])+"^"+hex(key[keyPos])+"=",
			dictionary[b]=dictionary[b]^key[keyPos]
			print hex(dictionary[b])+" ",
			keyPos=keyPos+1;
	ih.fromdict(dictionary);
	ih.write_hex_file(tmp);
encrypt();

