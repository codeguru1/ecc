CONTIKI = ../../contiki-2.7

ifndef TARGET
TARGET=cooja
endif

CONTIKI_ECC_DIR = ..

all: alice bob alice_ecdsa bob_ecdsa


ifeq ($(TARGET),cooja)
  CPU_ARCH = THIRTYTWO_BIT_PROCESSOR
  CPU = x86
endif

ifeq ($(TARGET),micaz)
  CPU_ARCH = EIGHT_BIT_PROCESSOR
  CPU = avr
endif

ifeq ($(TARGET),sky)
  CPU_ARCH = SIXTEEN_BIT_PROCESSOR
  CPU = msp430
endif

DOMAIN_PARAMS = SECP128R1

PROJECT_SOURCEFILES += messages.c
include $(CONTIKI_ECC_DIR)/Makefile.contikiecc

include $(CONTIKI)/Makefile.include
