#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2013-2014, NewAE Technology Inc
# All rights reserved.
#
# Find this and more at newae.com - this file is part of the chipwhisperer
# project, http://www.assembla.com/spaces/chipwhisperer
#
#    This file is part of chipwhisperer.
#
#    chipwhisperer is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    chipwhisperer is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with chipwhisperer.  If not, see <http://www.gnu.org/licenses/>.
#=================================================
import logging
import random
import re
from chipwhisperer.common.utils import util
from chipwhisperer.analyzer.utils.aes_funcs import key_schedule_rounds
from chipwhisperer.common.utils.aes_cipher import AESCipher
from ._base import AcqKeyTextPattern_Base

class AcqKeyTextPattern_TVLATTest_base3(AcqKeyTextPattern_Base):
    """Class for getting key and text for TVLA T-Tests.

    Basic usage::

        import chipwhisperer as cw
        ktp = cw.ktp.TVLATTest()
        ktp.init(num_traces) # init with the number of traces you plan to
                             # capture
        key, text = ktp.next()

    """
    _name = "TVLA Rand vs Fixed"
    _description = "Welsh T-Test with random/fixed plaintext."

    def __init__(self, target=None):
        AcqKeyTextPattern_Base.__init__(self)
        self._interleavedPlaintext = []
        self._key = []
        self._validchar = re.compile("[^01245689a']")


        self.setTarget(target)

    def _initPattern(self):
        pass

    def validateText(self):

        valid = self._validchar.search(self._textin.hex())

        if valid:
            raise ValueError("Invalid Base3 string: forbidden character: {}".format(valid[0]))

    def init(self, maxtraces):
        """Initialize key text pattern for a specific number of traces.

        Args:
            maxtraces (int): Number of traces to initialize for.

        Raises:
            ValueError: Invalid key length
        """
        length = self.keyLen()
        if length <= 32:
            self._key = util.hexStrToByteArray("00 11 22 44 55 66 88 99 aa 01 24 56 89 a0 12 45 68 9a 00 11 22 44 55 66 88 99 aa 01 24 56 89 a0")[:length]
        else:
            raise ValueError("Invalid key length: %d bytes" % length)

        self._textin1 = util.hexStrToByteArray("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")

        if length == 16:
            self._interleavedPlaintext = util.hexStrToByteArray("11 01 21 08 99 a4 55 46 aa a1 00 21 45 64 45 46")
        elif length == 24:
            self._interleavedPlaintext = util.hexStrToByteArray("11 01 21 08 99 a4 55 46 aa a1 00 21 45 64 45 02")
        elif length == 32:
            self._interleavedPlaintext = util.hexStrToByteArray("11 01 21 08 99 a4 55 46 aa a1 00 21 45 64 45 8a")
        else:
            raise ValueError("Invalid key length: %d bytes" % length)

        self.num_group1 = int(maxtraces/2)
        self.num_group2 = int(maxtraces - self.num_group1)

    def new_pair(self):
        rand = random.random()
        num_tot = self.num_group1 + self.num_group2
        if num_tot == 0:
            group1 = (rand < 0.5)
        else:
            cutoff = float(self.num_group1) / num_tot
            group1 = (rand < cutoff)

        if group1:
            '''
            This utilizes a slightly hacky method of generating the plaintext
            string to guarantee that it is a valid base 3 number in the format
            that is expected. It utilizes random.choices() to pick a number of
            valid characters out of the allowed character set and utilizes that
            as a means of randomizing the string, rather than following the
            exact methodology in the T-test paper (Goodwin 2011).

            (Specifically, this _does not_ use random.SystemRandom().choices()
            since there is no need for this key generation process to require
            cryptographic randomness.)

            Alternately, as a test, the results of the methodology in Goodwin
            2011 could be followed (pt_i = AES(K, pt_{i - 1}) and the resulting
            binary string translated to trinary and truncated to be the
            appropriate number of characters. (TODO)
            '''
            self._textin = self._textin1
            
            chars = "01245689a"

            self._textin1 = bytearray.fromhex(''.join(random.choices(chars, k=32)))

            if self.num_group1 > 0:
                self.num_group1 -= 1

        else:
            self._textin = self._interleavedPlaintext
            if self.num_group2 > 0:
                self.num_group2 -= 1

        # Check key works with target
        self.validateKey()
        self.validateText()

        return self._key, self._textin

    def next(self):
        """Returns the next key text pair

        Updates last key and text

        Returns:
            (key (bytearray), text (bytearray))

        Raises:
            ValueError: Invalid key length
            ValueError: Invalid plaintext character

        .. versionadded:: 5.1
            Added next
        """
        return self.new_pair()
