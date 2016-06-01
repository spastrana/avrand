

#include <Process.h>
#include <avr/wdt.h>

#define soft_reset()        \
do                          \
{                           \
    wdt_enable(WDTO_15MS);  \
    for(;;)                 \
    {                       \
    }                       \
} while(0)
Process p;
const int BUFF_SIZE = 20;

void setup() {
  // put your setup code here, to run once:
  Serial.begin(9600);    // opens serial port, sets data rate to 9600 bps
  Bridge.begin();
  while (!Serial){}
}

void softwareReset() {
  Serial.println ("Running pwd...");
  p.runShellCommand("pwd");
}
void printEEPROM () {
  uint16_t initaddr=0;
  uint16_t endaddr=1024;
  char myChar;
  uint16_t i, j, k, remainder;
  uint8_t precision = 4;
  char tmp[16];
  char format[128];
  Serial.print ("EEPROM memory from ");
  Serial.println ((int)initaddr, HEX);

  sprintf(format, "0x%%.%dX", 4);
  sprintf(tmp, format, initaddr);
  Serial.print(tmp);
  Serial.print("\t");
  k = 0;
  char* truncated;
  for (i = initaddr; i <= endaddr; i++, k++) {
    if (k % 16 == 0 && k != 0) {
      Serial.print("\t");
      for (j = i - 16; j < i; j++) {
        //address=(uint8_t*)j;
        myChar =  eeprom_read_byte((uint8_t*)(initaddr + j));
        if (((uint8_t)myChar < 0x20) || ((uint8_t)myChar > 0x7e))
          Serial.print(".");
        else
          Serial.print (myChar);
      }
      Serial.println();
      sprintf(format, "0x%%.%dX", 4);
      sprintf(tmp, format, i);
      Serial.print(tmp);

      // Serial.print (i,HEX);
      Serial.print ("\t");
    } else if (k % 8 == 0 && k != 0) {
      Serial.print("  ");
    }
    
    myChar =  eeprom_read_byte((uint8_t*)(initaddr + i));
    sprintf(format, "%%.%dX", precision);
    sprintf(tmp, format, myChar);
    
    Serial.print((char)*(tmp+2));
    Serial.print((char)*(tmp+3));
    Serial.print (" ");
  }
  i = k;
  remainder = 0;
  // Pad out last line if not exactly 16 characters.
  while ((k % 16) != 0) {
    Serial.print ("   ");
    if (k % 8 == 0)
      Serial.print("  ");
    k++;
    remainder++;
  }
  Serial.print ("\t");
  for (j = endaddr - 16 + remainder; j < endaddr; j++) {
    myChar =  eeprom_read_byte((uint8_t*)(initaddr + j));
    if (((uint8_t)myChar < 0x20) || ((uint8_t)myChar > 0x7e))
      Serial.print(".");
    else
      Serial.print (myChar);
  }
  Serial.println ();
}

void printFlashMemory (uint8_t* initaddr, uint8_t* endaddr) {
  char myChar;
  if (endaddr == (int)0)
    endaddr = (uint8_t*)0x7FFE;
  int i, j, k, remainder;
  int precision = 4;
  char tmp[16];
  char format[128];
  Serial.print ("Flash memory from ");
  Serial.println ((int)initaddr, HEX);

  sprintf(format, "0x%%.%dX", 4);
  sprintf(tmp, format, (int)initaddr);
  Serial.print(tmp);
  Serial.print("\t");
  k = 0;
  char* truncated;
  for (i = (int)initaddr; i <= (int)endaddr; i++, k++) {

    if (k % 16 == 0 && k != 0) {
      Serial.print("\t");
      for (j = i - 16; j < i; j++) {
        //address=(uint8_t*)j;
        myChar =  pgm_read_byte_near(initaddr + j);
        if (((int)myChar < 0x20) || ((int)myChar > 0x7e))
          Serial.print(".");
        else
          Serial.print (myChar);
      }
      Serial.println();
      sprintf(format, "0x%%.%dX", 4);
      sprintf(tmp, format, i);
      Serial.print(tmp);

      // Serial.print (i,HEX);
      Serial.print ("\t");
    } else if (k % 8 == 0 && k != 0) {
      Serial.print("  ");
    }
    //Serial.println ("Going to read byte at ");
    //Serial.println ((int)initaddr+i);
    
    myChar =  pgm_read_byte_near(initaddr + i);
    //Serial.print ("Read byte OK: ");
    //Serial.println (myChar);
    sprintf(format, "%%.%dX", precision);
    sprintf(tmp, format, myChar);
    /*truncated=(char*)malloc(2);
    strncpy(truncated, tmp+2, 2);*/
    
    Serial.print((char)*(tmp+2));
    Serial.print((char)*(tmp+3));
    //Serial.print(myChar,HEX);
    //free(truncated);
    Serial.print (" ");
  }
  i = k;
  remainder = 0;
  // Pad out last line if not exactly 16 characters.
  while ((k % 16) != 0) {
    Serial.print ("   ");
    if (k % 8 == 0)
      Serial.print("  ");
    k++;
    remainder++;
  }
  Serial.print ("\t");
  for (j = (int)endaddr - 16 + remainder; j < (int)endaddr; j++) {
    myChar =  pgm_read_byte_near(initaddr + j);
    if (((int)myChar < 0x20) || ((int)myChar > 0x7e))
      Serial.print(".");
    else
      Serial.print (myChar);
  }
  Serial.println ();
}


void printSRAM(uint8_t* initaddr, uint8_t* endaddr) {
  uint8_t* address;
  int i, j;
  int k = 0;
  int remainder;
  if ((int)endaddr == 0)
    endaddr = (uint8_t*)0xAFF;
  Serial.print ("Stack Pointer:");
  Serial.println(SP,HEX);
  Serial.print ("SRAM from ");
  Serial.println ((int)initaddr, HEX);
  Serial.print ((int)initaddr, HEX);
  Serial.print("\t");
  for (i = (int)initaddr; i <= (int)endaddr; i++, k++) {
    if (k % 16 == 0 && k != 0) {
      Serial.print("\t");
      for (j = i - 16; j < i; j++) {
        address = (uint8_t*)j;
        if (((int)*address < 0x20) || ((int)*address > 0x7e))
          Serial.print(".");
        else
          Serial.print ((char)(*address));
      }
      Serial.println();
      Serial.print (i, HEX);
      Serial.print ("\t");
    } else if (k % 8 == 0 && k != 0) {
      Serial.print("  ");
    }
    address = (uint8_t*)i;
    if ((int)*address < 0x10)
      Serial.print("0");
    Serial.print(*address, HEX);
    Serial.print (" ");
  }
  i = k;
  remainder = 0;
  // Pad out last line if not exactly 16 characters.
  while ((k % 16) != 0) {
    Serial.print ("   ");
    if (k % 8 == 0)
      Serial.print("  ");
    k++;
    remainder++;
  }
  Serial.print ("\t");
  for (j = (int)endaddr - 16 + remainder; j < (int)endaddr; j++) {
    address = (uint8_t*)j;
    if (((int)*address < 0x20) || ((int)*address > 0x7e))
      Serial.print(".");
    else
      Serial.print ((char)(*address));
  }
  Serial.println ();
}
void printStack(int initAddr) {
  void* initaddr = (void*)initAddr;
  uint8_t* address;
  int i, j;
  int k = 0;
  int remainder;
  uint8_t*  endaddr = (uint8_t*)0xAFF;
  //check_mem();

  Serial.println ("STACK:");
  Serial.print("0x");
  Serial.print ((int)initaddr, HEX);
  Serial.print("\t");
  for (i = (int)initaddr; i <= (int)endaddr; i++, k++) {
    if (k % 16 == 0 && k != 0) {
      Serial.print("\t");
      for (j = i - 16; j < i; j++) {
        address = (uint8_t*)j;
        if (((int)*address < 0x20) || ((int)*address > 0x7e))
          Serial.print(".");
        else
          Serial.print ((char)(*address));
      }
      Serial.println();
      Serial.print("0x");
      Serial.print (i, HEX);
      Serial.print ("\t");
    } else if (k % 8 == 0 && k != 0) {
      Serial.print("  ");
    }
    address = (uint8_t*)i;
    if ((int)*address < 0x10)
      Serial.print("0");
    Serial.print(*address, HEX);
    Serial.print (" ");
  }
  i = k;
  remainder = 0;
  // Pad out last line if not exactly 16 characters.
  while ((k % 16) != 0) {
    Serial.print ("   ");
    if (k % 8 == 0)
      Serial.print("  ");
    k++;
    remainder++;
  }
  Serial.print ("\t");
  for (j = (int)endaddr - 16 + remainder; j < (int)endaddr; j++) {
    address = (uint8_t*)j;
    if (((int)*address < 0x20) || ((int)*address > 0x7e))
      Serial.print(".");
    else
      Serial.print ((char)(*address));
  }
  Serial.println ();
}


int vulnerable_func () {
  volatile uint8_t tmp_buff [BUFF_SIZE];
  int i;

  printStack(SP);
  while (!Serial.available());
  i = 0;
  while (Serial.available()) {
    char c = Serial.read();  //gets one byte from serial buffer
    tmp_buff[i] = c;
    i++;
  }
  if (tmp_buff == NULL)
    return -1;
  printStack(SP);
  return 0;
}


void showOutputProcess() {
  while (p.running());

  Serial.println();
  while (p.available() > 0) {
    char c = p.read();
    Serial.print(c);
  }
  Serial.flush();
}

void processCommand(){
  //execute the command
    p.runShellCommand("ifconfig"); 
    showOutputProcess();
}


void loop() {
  // put your main code here, to run repeatedly:
  char option;
  Serial.println ("What do you want?");
  Serial.println ("1. Dump SRAM");
  Serial.println ("2. Dump Flash");
  Serial.println ("3. Dump EEPROM");
  Serial.println ("4. Run Vulnerable Function");
  Serial.println ("5. Software Reset");
  Serial.println ("6. Get network info");
  while (!Serial.available());

  option = Serial.read();  //gets one byte from serial buffer
  Serial.read();//NULL


  if (option == '1') {
    printSRAM((uint8_t*)0, (uint8_t*)0);
  } else if (option == '2') {
    printFlashMemory((uint8_t*)0, (uint8_t*)0);
  }else if (option=='3'){
    printEEPROM();
  } else if (option == '5') {
    Serial.println("Going to SW reset...");
    soft_reset();
  } else if (option == '4') {
    Serial.print ("Running vulnerable function...");
    int r = vulnerable_func ();
    Serial.print ("Vulnerable function ");
    if (r >= 0)
      Serial.println("OK");
    else
      Serial.println ("KO");
  }else if (option == '6'){
    processCommand();
  } else {
    Serial.print("Wrong option: ");
    Serial.println(option);
  }
}



