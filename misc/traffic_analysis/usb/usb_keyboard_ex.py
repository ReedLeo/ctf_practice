#! /usr/bin/env/python3
import sys

# 使用较新的wireshark提取的hid_data, 不以:分隔每个字节
def tran_hid_to_keyboard(hid_data):
    normal_keys = { 
        "04":"a", "05":"b", "06":"c", "07":"d", "08":"e",
        "09":"f", "0a":"g", "0b":"h", "0c":"i", "0d":"j",
        "0e":"k", "0f":"l", "10":"m", "11":"n", "12":"o",
        "13":"p", "14":"q", "15":"r", "16":"s", "17":"t",
        "18":"u", "19":"v", "1a":"w", "1b":"x", "1c":"y",
        "1d":"z","1e":"1", "1f":"2", "20":"3", "21":"4",
        "22":"5", "23":"6","24":"7","25":"8","26":"9",
        "27":"0","28":"<RET>","29":"<ESC>","2a":"<DEL>", "2b":"\t",
        "2c":"<SPACE>","2d":"-","2e":"=","2f":"[","30":"]","31":"\\",
        "32":"<NON>","33":";","34":"'","35":"<GA>","36":",","37":".",
        "38":"/","39":"<CAP>","3a":"<F1>","3b":"<F2>", "3c":"<F3>","3d":"<F4>",
        "3e":"<F5>","3f":"<F6>","40":"<F7>","41":"<F8>","42":"<F9>","43":"<F10>",
        "44":"<F11>","45":"<F12>"
    }
    shift_keys = { 
        "04":"A", "05":"B", "06":"C", "07":"D", "08":"E",
        "09":"F", "0a":"G", "0b":"H", "0c":"I", "0d":"J",
        "0e":"K", "0f":"L", "10":"M", "11":"N", "12":"O",
        "13":"P", "14":"Q", "15":"R", "16":"S", "17":"T",
        "18":"U", "19":"V", "1a":"W", "1b":"X", "1c":"Y",
        "1d":"Z","1e":"!", "1f":"@", "20":"#", "21":"$",
        "22":"%", "23":"^","24":"&","25":"*","26":"(","27":")",
        "28":"<RET>","29":"<ESC>","2a":"<DEL>", "2b":"\t","2c":"<SPACE>",
        "2d":"_","2e":"+","2f":"{","30":"}","31":"|","32":"<NON>","33":"\"",
        "34":":","35":"<GA>","36":"<","37":">","38":"?","39":"<CAP>","3a":"<F1>",
        "3b":"<F2>", "3c":"<F3>","3d":"<F4>","3e":"<F5>","3f":"<F6>","40":"<F7>",
        "41":"<F8>","42":"<F9>","43":"<F10>","44":"<F11>","45":"<F12>"
    }
    output = []
    for key in hid_data:
        try:
            if key[0]!='0' or (key[1]!='0' and key[1]!='2') or key[2]!='0' or key[3]!='0' or key[6]!='0' or key[7]!='0' or key[8]!='0' or key[9]!='0' or key[10]!='0' or key[11]!='0' or key[12]!='0' or key[13]!='0' or key[14]!='0' or key[15]!='0' or key[4:6]=="00":
                continue
            if key[4:6] in normal_keys.keys():
                output += [[normal_keys[key[4:6]]],[shift_keys[key[4:6]]]][key[1]=='2']
            else:
                output += ['[unknown]']
        except:
            pass

    flag=0
    print("".join(output))
    for i in range(len(output)):
        try:
            a = output.index('<DEL>')
            del output[a]
            del output[a-1]
        except:
            pass

    for i in range(len(output)):
        try:
            if output[i] == "<CAP>":
                flag += 1
                output.pop(i)
                if flag == 2:
                    flag = 0
            if flag != 0:
                output[i] = output[i].upper()
        except:
            pass
    
    return ''.join(output)

def do_extract(file_name):
    res = "!!UNKNOWN!!"
    with open(file_name, 'r') as f:
        res = tran_hid_to_keyboard(f)
        print(res)
    return res


if __name__ == '__main__':
    if (len(sys.argv) < 2):
        print(f"Usage: {sys.argv[0]} usbdata_file_name")
    else:
        do_extract(sys.argv[1])