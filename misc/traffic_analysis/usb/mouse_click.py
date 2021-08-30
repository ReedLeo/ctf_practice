#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse

# extract mouse click coordinates in "x y" format
# default detect the letf button click.
# @in_file_name: input file name. 
# @out_file_name: output file name.
# @button: 1 -- left button; 0 -- right button
def mouse_click_analyze(in_file_name, out_file_name, button=1):
    nums = []
    keys = open(in_file_name,'r')
    result = open(out_file_name,'w') # 最后生成的result.txt 是一个xxx xxx 形式的坐标集合，直接用gnuplot 画图即可
    posx = 0
    posy = 0
    for line in keys:
        if len(line) != 24 :
            continue
        x = int(line[6:8],16) #这是代表第三个字节，如果生成的usb.txt没有: 的话，这个改为 x = int(line[4:6],16)
        y = int(line[12:14],16) # 这是代表第五个字节，如需修改，与上面同理修改
        if x > 127 :
            x -= 256
        if y > 127 :
            y -= 256
        posx += x
        posy += y
        btn_flag = int(line[0:2],16)  # 1 for left(左键) , 2 for right(右键) , 0 for nothing(无按键)
        if btn_flag == button :
            result.write(str(posx)+' '+str(-posy)+'\n')
    keys.close()

if "__main__" == __name__:
    parser = argparse.ArgumentParser(description='Extract mouse click coordinate.')
    parser.add_argument('-i', '--input', metavar='[in_file_name]', type=str, required=True,
                        help='input file name, containing datas in "01:23:45:67:89:ab:cd:ef" format.')
    parser.add_argument('-o', '--output', metavar='[out_file_name]', type=str, required=True,
                        help='output file name, which will contain the coordinates in "x y" format.')
    parser.add_argument('-b', '--button', metavar='[0|1]', type=int, default=1,
                        help='The button you want to detect. 1 -- left button (DEFAULT); 0 -- right button')
    args = parser.parse_args()
    mouse_click_analyze(args.input, args.output, args.button)