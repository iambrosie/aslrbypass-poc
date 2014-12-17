#!/usr/bin/python
import sys
nameIn=sys.argv[1]
nameOut=sys.argv[2]
a0=int(sys.argv[3], 16)
a1=int(sys.argv[4], 16)
a2=int(sys.argv[5], 16)
a3=int(sys.argv[6], 16)

fin = open (nameIn, 'rb')
fout = open (nameOut, 'wb')
for i in range(80):
    c=fin.read(1)
    fout.write(c)

fout.write (chr(a0))
fout.write (chr(a1))
fout.write (chr(a2))
fout.write (chr(a3))

fout.close()
fin.close()
