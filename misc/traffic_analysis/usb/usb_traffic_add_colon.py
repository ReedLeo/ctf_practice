
#!/bin/usr/env python3
# -*- coding:utf-8 -*-
import argparse

def convert_by_add_colon(in_file, out_file):
    f = open('usbdata.txt','r')
    fi = open('out.txt','w')
    while 1:
        a = f.readline().strip()
        if a:
            if len(a) == 16:
                out = ''
                for i in range(0, len(a), 2):
                    out += a[i] + a[i+1]
                    if i + 2 != len(a):
                        out += ":"
                fi.write(out)
                fi.write('\n')
        else:
            break
    fi.close()

if "__main__" == __name__:
    parser = argparse.ArgumentParser(description='Convert USBHID.data to USB.capdata format.')
    parser.add_argument('-i', '--input', metavar='[in_file_name]', type=str, required=True,
                        help='input file name, containing datas in "0123456789abcdef" format.')
    parser.add_argument('-o', '--output', metavar='[out_file_name]', type=str, required=True,
                        help='output file name, which will contain data in "01:23:45:67:89:ab:cd:ef" format.')
    args = parser.parse_args()
    convert_by_add_colon(args.input, args.output)