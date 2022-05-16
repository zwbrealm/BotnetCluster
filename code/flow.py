class flow:
    def __init__(self,five_tuple):
        self.cnt = 0
        self.bytes = 0
        self.five_tuple = five_tuple
        self.time_seq =[]      #时间序列，到达的
    def time_add(self,time):
        self.time_seq.append(time)
    def set_cnt(self,cnt):
        self.cnt+=cnt
    def set_bytes(self,bytes):
        self.bytes+=bytes