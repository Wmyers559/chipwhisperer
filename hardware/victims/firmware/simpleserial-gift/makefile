# Hey Emacs, this is a -*- makefile -*-
#----------------------------------------------------------------------------
#
# Makefile for ChipWhisperer SimpleSerial-AES Program
#
#----------------------------------------------------------------------------
# On command line:
#
# make all = Make software.
#
# make clean = Clean out built project files.
#
# make coff = Convert ELF to AVR COFF.
#
# make extcoff = Convert ELF to AVR Extended COFF.
#
# make program = Download the hex file to the device, using avrdude.
#                Please customize the avrdude settings below first!
#
# make debug = Start either simulavr or avarice as specified for debugging, 
#              with avr-gdb or avr-insight as the front end for debugging.
#
# make filename.s = Just compile filename.c into the assembler code only.
#
# make filename.i = Create a preprocessed source file for use in submitting
#                   bug reports to the GCC project.
#
# To rebuild project do "make clean" then "make all".
#----------------------------------------------------------------------------

# Target file name (without extension). 
# This is the base name of the compiled .hex file.
TARGET = simpleserial-gift

# List C source files here.
# Header files (.h) are automatically pulled in.
SRC += simpleserial-gift.c gift/crypto.c

# -----------------------------------------------------------------------------
EXTRA_OPTS = NO_EXTRA_OPTS
CFLAGS += -D$(EXTRA_OPTS)

ifeq ($(CRYPTO_TARGET),)
CRYPTO_TARGET = NONE
endif

ifeq ($(CRYPTO_OPTIONS),)
CRYPTO_OPTIONS = AES128C
endif

#Add simpleserial project to build
include ../simpleserial/Makefile.simpleserial


FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc

# These are specific rules to swap the versions of the gift code
.PHONY: base4 base3 present32-speed present8-mem present32-mem

base4:
	@rm -f gift
	@ln -sf ~/Documents/gift_impl/gift gift

base3:
	@rm -f gift
	@ln -sf ~/Documents/gift_impl/giftBase3 gift

present8-mem:
	@rm -f gift
	@ln -sf ~/Documents/gift_impl/gift/8bit gift

present32-mem:
	@rm -f gift
	@ln -sf ~/Documents/gift_impl/gift/32bit gift
	@ln -sf ~/Documents/gift_impl/gift/32bit/mem_crypto.c gift/crypto.c
	@ln -sf ~/Documents/gift_impl/gift/32bit/mem_crypto.h gift/crypto.h


present32-speed:
	@rm -f gift
	@ln -sf ~/Documents/gift_impl/gift/32bit/ gift
	@ln -sf ~/Documents/gift_impl/gift/32bit/fast_crypto.c gift/crypto.c
	@ln -sf ~/Documents/gift_impl/gift/32bit/fast_crypto.h gift/crypto.h

