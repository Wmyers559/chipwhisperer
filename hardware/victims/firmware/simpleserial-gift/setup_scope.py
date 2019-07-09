#/usr/bin/env python

# Simple script to setup the ChipWhisperer hardware and settings for playing
# around with in python.
#
# Assumes that you are using an OPENADC chipwhisperer (LITE or PRO)

#PLATFORM = 'CWLITEARM'
PLATFORM = 'CW303'

import binascii
import os

import chipwhisperer as cw
import chipwhisperer.analyzer as cwa

scope = cw.scope(cw.scopes.OpenADC)
target = cw.target(scope)

# setup scope parameters
scope.gain.gain = 45
scope.adc.samples = 5000
scope.adc.offset = 0
scope.adc.basic_mode = "rising_edge"
scope.clock.clkgen_freq = 7370000
scope.clock.adc_src = "clkgen_x4"
scope.trigger.triggers = "tio4"
scope.io.tio1 = "serial_rx"
scope.io.tio2 = "serial_tx"
scope.io.hs2 = "clkgen"

if "STM" in PLATFORM or PLATFORM == "CWLITEARM" or PLATFORM == "CWNANO":
    prog = cw.programmers.STM32FProgrammer
elif PLATFORM == "CW303" or PLATFORM == "CWLITEXMEGA":
    prog = cw.programmers.XMEGAProgrammer
else:
    prog = None

import time
def reset_target(scope):
    if PLATFORM == "CW303" or PLATFORM == "CWLITEXMEGA":
        scope.io.pdic = 'low'
        time.sleep(0.05)
        scope.io.pdic = 'high_z' #XMEGA doesn't like pdic driven high
        time.sleep(0.05)
    else:  
        scope.io.nrst = 'low'
        time.sleep(0.05)
        scope.io.nrst = 'high'
        time.sleep(0.05)


#Set up some project-specific bits
fw_path = 'simpleserial-gift-{}.hex'.format(PLATFORM)
text = bytearray(b'\xba\xdc\x0f\xfe\xeb\xad\xf0\x0d')
test = text.copy()
keya = b'\x12\x34\x56\x78\x87\x65\x43\x21'
keyb = b'\xab\xab\x12\x34\xdf\xec\x2f\x3c'
keya = bytearray(keya)
keyb = bytearray(keyb)
key = keya + keyb
keya.reverse()
keyb.reverse()
test.reverse()

inv_key = keya + keyb
pt      = text * 2
inv_pt  = test * 2
