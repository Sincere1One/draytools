#!/usr/bin/env python

lookup = [0] * 256

for line in file('vigorcrypt.txt', 'r'):
	line = line.split('\t')
	if len(line) == 3:
		if lookup[int(line[2], 16)] != 0:
			print 'Duplicate ciphertext found in line: ', line
		lookup[int(line[2], 16)] = int(line[1], 16)

infile = file('config.cfg','rb')
data = infile.read()
infile.close()

outfile = file('config_decrypted.cfg','wb')
for i in range(len(data)):
	outfile.write(chr(lookup[ord(data[i])]))
outfile.close()
