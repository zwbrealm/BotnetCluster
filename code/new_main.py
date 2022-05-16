# coding=UTF-8

import numpy as np
import os
from flow import flow
from C_flow import C_flow
import scapy.all as scapy
from utils import *
from x_means import XMeans

def read_pcap(file_path):
    #构建Ci集合
    f_flow = []
    c_flow = []
    # 每个特征映射的维度
    hyper_para = 5
    c_fph = []
    c_ppf = []
    c_bpp = []
    c_bps = []
    # 计算fph,ppf,bpp,bps
    # 每个Ci的总的向量，就存储在这里
    all_vec = []
    # for i in range (len(file_path_list)):
    #     print(file_path_list[i])
    pkts = scapy.rdpcap(file_path)
        #上一个包到达时间
    prev_arrive = 0
    for p in pkts:
        if p.haslayer("IP"):
            proto = p["IP"].proto
            # 未完全建立的TCP连接（SYN包）
            if proto == 6 and p['IP']['TCP'].flags == 'S':
                continue
            # 提取TCP或UDP包
            elif proto == 6 or proto == 17:
                src_ip = p["IP"].src
                dst_ip = p["IP"].dst
                try:
                    sport = p.payload.sport
                    dport = p.payload.dport
                except AttributeError:
                    continue
                time = p.time

                bytes = len(p)
                #fph更新

                five_tuple = [src_ip,sport,dst_ip,dport,proto]
                #转换成可哈希结构
                five_tuple = tuple(five_tuple)
                #过滤掉从server端发来的流
                if five_tuple[0][0:7]!='192.168':
                    continue
                #如果能找到对应的相同五元组的流,就直接处理
                if find_tuple_and_update(f_flow, five_tuple,time,bytes):
                    continue
                #否则加入f_flow中，这时并没有判断是否是同一时期的流
                else:
                    # 新创建一个C_flow对象,并给他的成员变量赋值
                    new_flow = flow(five_tuple)
                    new_flow.cnt = 1
                    new_flow.time_seq = [time]
                    new_flow.bytes = bytes
                    f_flow.append(new_flow)
    # 查看是否是不同时期的同一种流

    for f in f_flow:
        # 剔除掉那些只出现一次的流，因为他的开始时间和结束时间无法计算
        if f.cnt == 1:
            continue
        if compare_and_merge(c_flow,f):
            pass
        #如果未匹配上，自立门户
        else:
            new_flow = C_flow(f.five_tuple)
            new_flow.bytes = [f.bytes]
            new_flow.time_seq = [f.time_seq]
            new_flow.cnt = [f.cnt]
            c_flow.append(new_flow)

    for item in c_flow:
        item.fph()
        item.ppf()
        item.bpp()
        item.bps()


        a = cut(item.fph,hyper_para)
        b = cut(item.ppf,hyper_para)
        c = cut(item.bpp,hyper_para)
        d = cut(item.bps,hyper_para)
        #所有Ci四种特征每种有 ：n个维度

        #定义当前Ci的向量，4*n维
        item_vec = []
        item_vec.extend(a)
        item_vec.extend(b)
        item_vec.extend(c)
        item_vec.extend(d)
        #所有Ci的向量集合all_vec
        all_vec.append(item_vec)

    return all_vec,c_flow


def day_pcap_collect(device,days_num):
    # root  = ''
    day_pcap_list = os.listdir(device)
    for i in range(days_num):
        day_pcap_list[i] = device +'/'+day_pcap_list[i]
    # print(day_pcap_list)
    return day_pcap_list[:days_num]
def device_run(device_name,days_num):
    print(device_name)
    file_list = day_pcap_collect(device_name,days_num)
    with open('method2_debug_20_21.txt', 'a') as f:
        f.write('--------------------'+device_name+'--------------------------'+'\n')
        f.close()
    all_vec, c_flow = [],[]
    # all_vec, c_flow, c_fph, c_ppf, c_bpp, c_bps = np.array([]),np.array([]),np.array([]),np.array([]),np.array([]),np.array([])
    file_index = 0
    for file_index in range(len(file_list)):
        all_vec, c_flow = read_pcap(file_list[file_index])
        if all_vec!=[]:
            break
    cnt = 0
    with open('method2_debug_20_21.txt', 'a') as f:
        for i in c_flow:
            f.write(str(cnt) + ':' + str(i.five_tuple) + '\n')
            cnt += 1
    f.close()
    print('HANDLE COMPLETE')
    all_vec = np.array(all_vec)
    for pcap_file in file_list[file_index:days_num]:
        print('HAVE START ONE')
        tmp_all_vec, tmp_c_flow = read_pcap(pcap_file)
        if tmp_all_vec ==[]:
            continue
        with open('method2_debug_20_21.txt', 'a') as f:
            for tmp in tmp_c_flow:
                f.write(str(cnt) + ':' + str(tmp.five_tuple) + '\n')
                cnt += 1
        f.close()
        tmp_all_vec = np.array(tmp_all_vec)
        all_vec = np.concatenate((all_vec,tmp_all_vec),axis=0)
    # if c_fph.shape[0] == 1:
    # print(all_vec)
    res1 = coarse_grained_cluster_and_evaluate(all_vec)
    res2 = fine_grained_cluster(all_vec,res1,8)
    with open('method2_res_20_21.txt','a') as f:
        f.write('----------Device name:--------------'+device_name+'------------------------------------------\n')
        f.write('1. result of first cluster stage: '+str(res1)+'\n')
        f.write('2. result of second cluster stage:'+str(res2)+'\n')
        f.write('\n')
    f.close()


device_list = ['360_camera','360_doorbell','aqara_gateway','biu_speaker','ezviz_camera','gree_gateway','gree_plug','hichip_battery_camera','honyar_outlet','ihorn_gateway','mercury_wirecamera','miai_soundbox','philips_camera','skyworth_camera','tcl_gateway','tmall_genie','tplink_camera','wiz_led','xiaodu_audio','xiaomi_camera','xiaomi_gateway','xiaomi_plug']
device_list = device_list[20:21]
for device_name in device_list:
    device_run(device_name, 7)
# device_run('new_file/2',3)
