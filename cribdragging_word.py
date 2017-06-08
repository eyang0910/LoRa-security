

# Author: Xueying Yang
# EMail: yangxueying0910@hotmail.com
# This program is to use crib dragging to decrease the possibilities of plaintext for words.


# This is for test 5468697320697320666F722074657374
# QJmZmZkALwEJi4BJ/CLRJGt9eVZOAvDTdjXoHbw= 4099999999002F01 09 8B8049FC22D1246B7D79564E02F0D376 35E81DBC
# Security matters 7365637572697479206D617474657273
# QJmZmZkALwEKrI1D+nDRIzI7e0UaAvDScQIsXs0= 4099999999002F01 0A AC8D43FA70D123323B7B451A02F0D271 022C5ECD

import itertools
import binascii
import base64
def xor2messages(message1,message2):
    # frmpayload1 = binascii.a2b_base64(message2)
    dic_len = 55
    phypayload_hex1 = binascii.hexlify(base64.decodestring(message1))
    phypayload_hex2 = binascii.hexlify(base64.decodestring(message2))
    frmpayload1 = phypayload_hex1[18:-8]
    frmpayload2 = phypayload_hex2[18:-8]
    frmpayload1=frmpayload1.zfill(max(len(frmpayload2),len(frmpayload1)))
    frmpayload2=frmpayload2.zfill(max(len(frmpayload2),len(frmpayload1)))
    # if len(frmpayload2) >= len(frmpayload1):
    #     fill_len = frmpayload2
    print frmpayload1
    print frmpayload2
    guessword = ' abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,.'
    guessword = list(guessword)
    cipher2_int = int(frmpayload1, 16) ^ int(frmpayload2, 16)
    cipher2_hex = hex(cipher2_int)[2:].zfill(max(len(frmpayload2),len(frmpayload1)))
    if cipher2_hex[-1] == 'L':
        cipher2_hex = cipher2_hex[:-1]
    print 'message length is', len(cipher2_hex)/2, '. Now make a guess!'
    while 1:
        guess_asc = raw_input()
        if guess_asc != "":
            guess_hex = binascii.b2a_hex(guess_asc)
            guess_len = len(guess_hex)
            str = ''
            for i in range((len(cipher2_hex) - guess_len+1)/2 +1):
                guess_comp = guess_hex + str
                # print str
                xorresult_hex = hex(int(guess_comp,16) ^ cipher2_int)[2:]
                if xorresult_hex[-1] == 'L':
                    xorresult_hex = xorresult_hex[:-1]
                # print xorresult_hex
                xorresult_ascii = binascii.a2b_hex(xorresult_hex.zfill(len(cipher2_hex)))
                for i in range(len(xorresult_ascii)):
                    corr_word = list(xorresult_ascii[i:i+len(guess_asc)])
                    if len(corr_word) == len(guess_asc):
                    # print set(corr_word).difference(guessword)
                        if set(corr_word).difference(guessword) == set([ ]):
                            print corr_word, 'message length now is' ,len(corr_word)
                # print xorresult_ascii, guess_comp,cipher2_int
                str += '00'
        else:
            break


xor2messages('QJmZmZkALwEJi4BJ/CLRJGt9eVZOAvDTdjXoHbw=','QJmZmZkALwEKrI1D+nDRIzI7e0UaAvDScQIsXs0=')

