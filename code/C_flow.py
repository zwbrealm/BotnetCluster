from flow import flow
from utils import *
class C_flow:
    def __init__(self,five_tuple):
        self.five_tuple = five_tuple
        self.cnt = []
        self.bytes = []
        self.time_seq = []


    def fph(self):
        self.fph = [0]*24
        for i in self.time_seq:
            for j in i:
                hour = time_convert(j)
                self.fph[hour] += 1
    def ppf(self):
        self.ppf = self.cnt

    def bpp(self):
        self.bpp = []
        for i in range(0,len(self.bytes)):
            bytes_per_packet = float(self.bytes[i])/self.cnt[i]
            self.bpp.append(bytes_per_packet)

    def bps(self):
        self.bps = []
        #一个Ci只有一条fi
        if(len(self.time_seq) == 1):
            # print(self.time_seq)
            print(len(self.time_seq[0]))
            duration = self.time_seq[0][-1] - self.time_seq[0][0]
            bytes = self.bytes[0]
            bytes_per_sec = float(bytes) /float(duration)
            self.bps.append(bytes_per_sec)
        else:
            for i in range(len(self.time_seq)):
                # print(self.time_seq[i])
                if self.time_seq[i][-1] != self.time_seq[i][0]:
                    duration = self.time_seq[i][-1] - self.time_seq[i][0]
                else:
                    duration = 0.05
                bytes = self.bytes[i]
                # print('time:', self.time_seq[i][-1], self.time_seq[i][0],len(self.time_seq))
                print(self.time_seq[i][-1],self.time_seq[i][0],len(self.time_seq[i]),bytes)
                bytes_per_sec = float(bytes)/float(duration)

                self.bps.append(bytes_per_sec)
