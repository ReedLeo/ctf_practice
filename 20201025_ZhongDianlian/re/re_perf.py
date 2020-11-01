import os
import sys
import subprocess

class Shell(object):
    def runCmd(self, cmd):
        res = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        sout, serr = res.communicate()
        return res.returncode, sout, serr, res.pid

    def initPin(self, cmd):
        res = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.res = res

    def pinWrite(self, input):
        self.res.stdin.write(input)

    def pinRun(self):
        sout, serr = self.res.communicate()
        return sout, serr

cmd = 'perf stat -x : -e instructions:u ./babyre'

shell = Shell()

s = ""
import string
chs=string.printable
for i in range(48):
	max_num = 0
	max_ch = ""
	for ch in chs:
		tmp = s + ch + (48-len(s)-1)*'a'
		shell.initPin(cmd)
		shell.pinWrite(tmp)
		sout, serr = shell.pinRun()
		count = int(sout.split(":")[5])
		if (count > max_num):
			max_num = count
			max_ch = ch
	s += max_ch
	print(s)
