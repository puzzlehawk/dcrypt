#!/bin/python
# use with http://ed25519.cr.yp.to/python/sign.input as input
import fileinput

print("immutable string[][] testVectors = [");
for line in fileinput.input():
 fields = line.split(":")
 print("\t[x\""+fields[0]+"\", x\"" + fields[1] + "\", x\"" + fields[2] + "\", x\"" + fields[3] + "\"],")

print("];");
