"""
Package containing all of the key text generation types

KTP:
* Basic - fixed/random key and text (default fixed key, random text)
* DPA - Applies mask to random plaintext, then randomly undoes it
* TVLATTest
* TVLATTest_base3 - Produces a fixed key and random text, but with the
    constraint of the values being valid base3 numbers
"""
from .basic import AcqKeyTextPattern_Basic as Basic
from .dpahelper import AcqKeyTextPattern_DPA as DPA
from .tvlattest import AcqKeyTextPattern_TVLATTest as TVLATTest
from .tvlattest_base3 import AcqKeyTextPattern_TVLATTest_base3 as TVLATTest_base3
