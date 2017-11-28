# genja3
A short program to parse a packet capture for ClientHellos and to generate JA3 hashes
for handshakes. Output is similar to that produced by the python script published by the
JA3 creators, though there are also additional options for displaying different data.

For matching JA3 hashes against published fingerprints, makes use of both
uthash (https://troydhanson.github.io/uthash/) and ujson4c (https://github.com/esnme/ujson4c).
The former allows every connection to be conveniently checked for a match; the latter allows
JSON files of fingerprints to be easily parsed.
