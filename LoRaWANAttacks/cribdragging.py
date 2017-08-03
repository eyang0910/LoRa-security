# Author: Xueying Yang
# EMail: yangxueying0910@hotmail.com
# This program is to use crib dragging to decrease the possibilities of plaintext.
# coding=utf-8
import binascii
import base64
import itertools

class cribdragging(object):


    def info_prep(self):

        """
        This function is to load the gateway log files from different communication sessions and extract the payloads from log.
        Outputs are counter numbers and physical payloads.
        Counter numbers are selected from physical payloads. If same counter value are shown in all the sessions, then it will be selected.
        """
        devaddr_def = '99999999'
        prd_num = 4
        info =[]
        path = ["/home/xueying/PycharmProjects/cribdragging/gateway_0406_l1.txt","/home/xueying/PycharmProjects/cribdragging/gateway_0406_l2.txt","/home/xueying/PycharmProjects/cribdragging/gateway_0406_l3.txt","/home/xueying/PycharmProjects/cribdragging/gateway_0406_l4.txt"]
        # path =["/home/xueying/PycharmProjects/cribdragging/gatewaylog.txt","/home/xueying/PycharmProjects/cribdragging/gatewaylog_l2.txt","/home/xueying/PycharmProjects/cribdragging/gatewaylog_l3.txt","/home/xueying/PycharmProjects/cribdragging/gatewaylog_l4.txt"]
        for i in range(prd_num):
            file = open(path[i],"r")
            info.append(file.readlines())

        payload_g = [[] for i in range(prd_num)]
        for j in range(prd_num):
            for i in range(len(info[j])):
                if 'rxInfo' in info[j][i]: # Only select messages with rxInfo, which indicates this is a communication related message,
                    phy_index = info[j][i].index('phyPayload')
                    payload_g[j].append(info[j][i][phy_index+13:-3])

        phy_hex = [[]for i in range(prd_num)]
        ctr = [[]for i in range(prd_num)]
        devaddr = [[]for i in range(prd_num)]
        for j in range(prd_num):
            for i in range(len(payload_g[j])):
                phy_hex[j].append(binascii.hexlify(base64.decodestring(payload_g[j][i])))
                ctr[j].append(phy_hex[j][i][12:16]) # Choose counter value
                devaddr[j].append(phy_hex[j][i][2:10])



        # print ctr
        msg_group = []
        ctr_op =[]
        for j in range(len(ctr[0])):
                if ctr[0][j] in ctr[1] and ctr[0][j] in ctr[2]and ctr[0][j] in ctr[3]:
                    # 4 sessions indicated. How to optimize it?
                    ctr_index1 = ctr[1].index(ctr[0][j])
                    ctr_index2 = ctr[2].index(ctr[0][j])
                    ctr_index3 = ctr[3].index(ctr[0][j])
                    ctr_op.append(int(ctr[0][j][0:2],16))
                    if devaddr[0][j] == devaddr[1][ctr_index1] == devaddr[2][ctr_index2] == devaddr[3][ctr_index3] =='99999999':

                        msg_group.append([payload_g[0][j], payload_g[1][ctr_index1], payload_g[2][ctr_index2], payload_g[3][ctr_index3]])
                    else:
                        print '===============devaddr wrong',devaddr[0][j],devaddr[1][ctr_index1], devaddr[2][ctr_index2],devaddr[3][ctr_index3]
        # print ctr_op
        return msg_group,ctr_op

    def xor2messages(self,message):

        guessword_hex_len = 2
        guessword = [' ', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        msg_num = len(message)
        phypayload_hex = []
        frmpayload = []
        cipher_int = []
        cipher_hex = []
        guessword_hex = []
        cipher_hex_message = []
        k = 0
        frm_len = 16
        msg_len = 8

        # guessword ascii -> hex
        for i in range(len(guessword)):
            guessword_hex.append(binascii.b2a_hex(guessword[i]))

        # choose framepayloads(hex)
        for i in range(msg_num):
            phypayload_hex.append(binascii.hexlify(base64.decodestring(message[i])))
            frmpayload.append(phypayload_hex[i][18:-8])

        # traverse xor results of 2 frame payloads
        for i in range(msg_num):
            for j in range(i+1,msg_num):
                cipher_int.append(int(frmpayload[i], frm_len) ^ int(frmpayload[j], frm_len))
                if hex(cipher_int[k])[-1] == 'L':
                    cipher_hex.append(hex(cipher_int[k])[2:-1].zfill(frm_len))
                elif hex(cipher_int[k])[1] == 'x':
                    cipher_hex.append(hex(cipher_int[k])[2:].zfill(frm_len))
                else:
                    cipher_hex.append(hex(cipher_int[k]).zfill(frm_len))
                cipher_hex_message.append([i,j])
                k += 1


        # traverse xor results of 2 framepayload (ciphertexts) and 1 guessword(plaintext) and change it to ascii
        # Note that all the positions are tried.
        xorresult = [[[] for k in range(msg_len)] for k in range(len(cipher_hex))]
        result_plain = [[[] for k in range(msg_len)] for k in range(len(cipher_hex))]
        grab_cipher=[[]for k in range(len(cipher_hex))]
        for j in range(len(cipher_hex)):
            for i in range (msg_len):
                grab_cipher[j].append(cipher_hex[j][2 * i:2 * i + guessword_hex_len])
                for k in range(len(guessword)):
                    xorresult_hex = hex(int(grab_cipher[j][i], 16) ^ int(guessword_hex[k], 16))[2:].zfill(guessword_hex_len)
                    xorresult_ascii = binascii.a2b_hex(xorresult_hex)
                    xorresult[j][i].append(xorresult_ascii)


        # Determine whether the reuslt is in guessword (readable, and meet the requirements of LoRaWAN evaluation kit)
        # The result is compared between every 2 messages
        for j in range(len(cipher_hex)):
            # print '############################### Message number is', cipher_hex_message[j], '#################################################################'
            for i in range(msg_len):
                for k in range(len(guessword)):
                    if xorresult[j][i][k] in guessword:
                        a = xorresult[j][i][k]
                        b = guessword[k]
                        if xorresult[j][i][guessword.index(a)] == b:
                            result_plain[j][i].append([a, b])
                # use '/' to represent \x00
                if len(result_plain[j][i]) == 0 :
                    result_plain[j][i] = [[binascii.a2b_hex(cipher_hex[j][2 * i:2 * i + 2]), '/'],['/',binascii.a2b_hex(cipher_hex[j][2 * i:2 * i + 2])]]
                elif len(result_plain[j][i]) == 11 :
                    result_plain[j][i].append(['/','/'])
                # print cipher_hex[j],'Position', i, xorresult[j][i], 'Plaintext can be', result_plain[j][i], '. Total:', len(result_plain[j][i]), 'choices'

        # Condition 1: plaintext is in numbers
        P = [[[ ] for k in range(msg_num)] for k in range(msg_len)]
        for j in range(msg_len):
            for i in range (msg_num):
                P[j][i] = ['*' for m in range(len(guessword)+1)]

        for j in range(msg_num-1):
            for i in range(msg_len): # different postions
                for k in range(len(result_plain[j][i])): # different pairs
                    if j == 0:
                        ps = cipher_hex_message[j][0] # message 1
                        pe = cipher_hex_message[j][1] # message 2
                        P[i][ps][k] = result_plain[j][i][k][0]
                        P[i][pe][k] = result_plain[j][i][k][1]
                    else:
                        if result_plain[j][i][k][0] in P[i][0]:
                            index = P[i][0].index(result_plain[j][i][k][0])
                            pe = cipher_hex_message[j][1]  # message 2
                            P[i][pe][index] = result_plain[j][i][k][1]


    # Condition 2: It is not possible for plain text to start with 0
        Pa = [[]for m in range(msg_len)]
        pairs = [[]for j in range(msg_len)]
        for j in range(msg_len):
            Pa[j] = map(list, zip(*P[j]))

            for i in range(len(guessword)+1):
                # print j, i, Pa[j][i]
                if j == 0:
                    if '*' not in Pa[j][i] and '0' not in Pa[j][i]:
                        pairs[j].append(Pa[j][i])
                else:
                    if '*' not in Pa[j][i]:
                        pairs[j].append(Pa[j][i])

            # print 'Position is', j, pairs[j]

    # Condition 3: It is not possible to have 3 numbers in one message
        for k in range(msg_num):
            for j in range(len(pairs[msg_len-1])):
                # print k,j,pairs[msg_len-1][0]
                if pairs[msg_len-2][0][k] == '/' and pairs[msg_len-1][j][k] != '/':
                    del(pairs[msg_len-1][j])
                    break
                break
            break

        nums = 1
        for i in range(msg_len):
            nums *= len(pairs[i])
        # print 'there are ', nums, ' options'

        # print pairs
        # Generate all message options

        new_pair  =list(itertools.product(pairs[0],pairs[1],pairs[2],pairs[3],pairs[4],pairs[5],pairs[6],pairs[7]))
        msg_comb = [[[]for i in range(nums)] for j in range(4)]
        msg_comb2 = []
        msg_comb = map(list, zip(*msg_comb))
        for i in range(len(new_pair)):
            for j in range(len(new_pair[i])):
                for k in range(4):
                    msg_comb[i][k].append(new_pair[i][j][k] )

        # Condition 4: temperature must be 3 digits
        # Condition 5; there is must be one and only one space
        # Condition 6: temperature is between -40 to 150, and light is under 1200


        for k in range(len(new_pair)):
            m = 0
            for i in range(4):
                if msg_comb[k][i].count(' ') == 1:
                    space_ind = msg_comb[k][i].index(' ')
                    temp_s = msg_comb[k][i][space_ind + 1:]
                    del_num = temp_s.count('/')

                    for p in range(del_num):
                        temp_s.remove('/')

                    if len(temp_s) ==3 :
                        temp_s2 = (''.join(temp_s))
                        light = msg_comb[k][i][:space_ind]
                        light2 = (''.join(light))
                        if ((int(temp_s2) >= 0) and (int(temp_s2) <= 100)) or ((int(temp_s2 )>= 200) and (int(temp_s2) <= 210)):
                                if int(light2) >= 0 and int(light2) <= 1200:
                                    m += 1
                                    # print int(temp_s2),temp_s2
                                else:
                                    break
                        else:
                            break
                    else:
                        break
                else:
                    break
            if m == 4:
                msg_comb2.append(msg_comb[k])
                # print '*********', k,msg_comb[k]
        return msg_comb2,len(msg_comb2)

    def realresult(self):
        """
        Import log files of application server, which indicate all plaintexts

        """
        prd_num = 4
        # path = ["/home/xueying/PycharmProjects/cribdragging/applog.txt","/home/xueying/PycharmProjects/cribdragging/applog_l2.txt","/home/xueying/PycharmProjects/cribdragging/applog_l3.txt","/home/xueying/PycharmProjects/cribdragging/applog_l4.txt"]
        path = ["/home/xueying/PycharmProjects/cribdragging/app_0406_l1.txt","/home/xueying/PycharmProjects/cribdragging/app_0406_l2.txt","/home/xueying/PycharmProjects/cribdragging/app_0406_l3.txt","/home/xueying/PycharmProjects/cribdragging/app_0406_l4.txt"]
        info = []
        for i in range(prd_num):
            file = open(path[i], "r")
            info.append(file.readlines())

        data_app_base64 = [[] for i in range(prd_num)]
        data_app_hex = [[] for i in range(prd_num)]
        ctr_app = [[] for i in range(prd_num)]
        data_app_ascii =  [[] for i in range(prd_num)]
        for j in range(prd_num):
            for i in range(len(info[j])):
                if '"data"' in info[j][i]:
                    data_index = info[j][i].index('"data"')
                    data_app_base64[j].append(info[j][i][data_index + 8:-3])
                    ctr_index = info[j][i].index('fCnt')
                    ctr_app[j].append(int(info[j][i][ctr_index + 6:ctr_index + 9]))
                    data_app_hex[j].append(binascii.hexlify(base64.decodestring(info[j][i][data_index + 8:-3])))
                    data_app_ascii[j].append(binascii.a2b_hex(data_app_hex[j][i]))
                    data_app_ascii[j][i] = list(data_app_ascii[j][i])
                    pattern = ['\x00']
                    data_app_ascii[j][i] = ['/' if x in pattern else x for x in data_app_ascii[j][i]]
        return data_app_ascii,ctr_app

msg_group, ctr_real = cribdragging().info_prep()
data_app,ctr_app = cribdragging().realresult()
cal_result = []
option = []
for i in range(len(msg_group)):
    cal,op = cribdragging().xor2messages(msg_group[i])
    cal_result.append(cal)
    option.append(op)

prd_num = 4
index_ctr = [[] for i in range(prd_num)]
data_new = [[] for i in range(prd_num)]
for i in range(len(ctr_real)):
    for j in range(prd_num):
        index_ctr[j].append(ctr_app[j].index(ctr_real[i]))

for i in range(len(index_ctr)):#4
    for j in range(len(ctr_real)):#9
        data_new[i].append(data_app[i][index_ctr[i][j]])

new = [[]for i in range(len(ctr_real))]
for i in range(len(ctr_real)):
    for j in range(prd_num):
        new[i].append(data_new[j][i])
a = []
for i in range(len(new)):
    print 'Sample:',i,
    if new[i] in cal_result[i]:
        print ' Calculation result is true. There are', len(cal_result[i]),'results.'
        a.append(len(cal_result[i]))
    else:
        print 'Calculation result is false'
    for j in range(len(cal_result[i])):
        print 'Option:',j,cal_result[i][j]

print a