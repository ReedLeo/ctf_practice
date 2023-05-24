# uncompyle6 version 3.9.0
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.10.4 (main, Mar 24 2022, 13:07:27) [GCC 11.2.0]
# Embedded file name: sample.py
footprint = '3qzqns4hj6\neeaxc!4a-%\nd735_@4l6g\nf1gd1v7hdm\n1+$-953}81\na^21vbnm3!\n-#*f-e1d8_\n2ty9uipok-\n6r1802f7d1\n9wez1c-f{0'
xx0000 = []
footprintlist = footprint.split('\n')
for i in range(len(footprintlist)):
    xx0000.append(list(footprintlist[i]))
else:

    def xxxx000x0(num):
        xx000000 = format(num, '010b')
        return xx000000


    oxooxxxxxoooo = [511,112,821,949,517,637,897,575,648,738]
    # xx0000000 = input("Please enter the previous 10 digits again and ending with '\\n': ").split(' ')
    # if len(xx0000000) == 10:
    #     try:
    #         for i in xx0000000:
    #             oxooxxxxxoooo.append(int(i))

        # except:
        #     print('err input!')
        #     exit(-1)

    # else:
    #     print('err input!')
    #     exit(-1)
    for i in range(len(oxooxxxxxoooo)):
        oxooxxxxxoooo[i] = list(xxxx000x0(oxooxxxxxoooo[i]))
        for x in oxooxxxxxoooo[i]:
            print(f'{x}, ', end="")
        print("")
    else:
        xx0000x000 = oxooxxxxxoooo
        x, o = (0, 0)
        xx00x00x0xxx00 = [(x, o)]
        xx00x00x0xxx00input = 'sddsdssdddwwwddsssssaaaaassddsddwdds' #list(input('input maze path:'))
        count = 0
        while (x, o) != (9, 9):
            if count < len(xx00x00x0xxx00input):
                xx0000x0xxx00 = xx00x00x0xxx00input[count]
                if xx0000x0xxx00 == 'a':
                    if o > 0 and xx0000x000[x][o - 1] == '0':
                        o -= 1
                        count += 1
                        xx00x00x0xxx00.append((x, o))
                    else:
                        print('wrong!')
                        exit(-1)
                elif xx0000x0xxx00 == 'd':
                    if o < 9 and xx0000x000[x][o + 1] == '0':
                        count += 1
                        o += 1
                        xx00x00x0xxx00.append((x, o))
                    else:
                        print('wrong!')
                        exit(-1)
                else:
                    if xx0000x0xxx00 == 'w':
                        if x > 0 and xx0000x000[x - 1][o] == '0':
                            count += 1
                            x -= 1
                            xx00x00x0xxx00.append((x, o))
                        else:
                            print('wrong!')
                            exit(-1)
                    else:
                        if xx0000x0xxx00 == 's':
                            if x < 9 and xx0000x000[x + 1][o] == '0':
                                count += 1
                                x += 1
                                xx00x00x0xxx00.append((x, o))
                            else:
                                print('wrong!')
                                exit(-1)
                        else:
                            print('wrong!')
                            exit(-1)
            else:
                print('wrong!')
                exit(-1)
        for x, y in xx00x00x0xxx00:
            print(footprintlist[x][y], end='')
        print("")    
        # 3eea35d-953744a-6d838d1e-f9802c-f7d10
        print('right! you maybe got it,flag is flag{the footprint of the maze path}')