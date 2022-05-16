from copy import deepcopy
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
                # sport = p.payload.sport

                #如果sport是字符串
                # try:
                #     sport = p.payload.sport
                #     dport = p.payload.dport
                # except AttributeError:
                #     continue

                try:
                    sport = p.payload.sport
                    dport = p.payload.dport
                except AttributeError:
                    continue
                time = p.time
                # else:
                #     continue
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
        c_fph.append(a)
        c_ppf.append(b)
        c_bpp.append(c)
        c_bps.append(d)
        #定义当前Ci的向量，4*n维
        item_vec = []
        item_vec.extend(a)
        item_vec.extend(b)
        item_vec.extend(c)
        item_vec.extend(d)
        #所有Ci的向量集合all_vec
        all_vec.append(item_vec)

    # all_vec = np.array(all_vec)
    print(all_vec)
    #返回流种值，第一个用于第二级聚类，第二个用于同下标时提供信息，第三-六个用于第一季聚类的降维
    #所有Ci的所有特征 +四种分别的特征
    # for i in c_flow:
    #     print('flow的包数：'+str(i.cnt)+'五元组'+str(i.five_tuple))
    return all_vec,c_flow,c_fph,c_ppf,c_bpp,c_bps
#搞成C流的形式
# flow_cnt_C = deepcopy(flow_cnt)
#
# for i in flow_cnt.keys():
#     for j in flow_cnt.keys():
#         if i[0] == j[0] and i[2] == j[2] and i[1]!=j[1] and i[3] == j[3]:
#             #不同时间的两个流实现聚合
#             flow_cnt_C[i] = flow_cnt_C[i] + flow_cnt_C[j]
#             del flow_cnt_C[j]

# https://blog.csdn.net/weixin_39831705/article/details/110910204
#对C-flow一阶段聚类
def cluster_1(a,b,c,d):
    #降到只剩八维
    a = sqeenze(a)
    b = sqeenze(b)
    c = sqeenze(c)
    d = sqeenze(d)
    reduced_array = np.concatenate((a,b,c,d), axis=1)
    #接下来写，如何用X-means聚类。X-means需要聚几类的参数n，需要data + label
    xm= XMeans()
    # ？标签如何确定
    xm.fit(reduced_array)
    label_pred = xm.labels_  # 获取聚类后的样本所属簇对应值
    centroids = xm.cluster_centers_  # 获取簇心

    cluster_indexes = split_index(label_pred)
    print(cluster_indexes)
    return cluster_indexes

#二阶段聚类,在cluster_1形成结果的内部集合聚类
#indexes是指第一阶段聚类后返回的结果，是一个二维的list:第二维是返回的是第一阶段的聚类结果
def cluster_2(indexes,all_vec):
    total_cluster_res = []
    #标记细分类之后的类别
    classid = 0
    for cluster_index in indexes:
        cluster_data = []
        #在all_vec这个未降维的所有样本的结果种寻找：
        #寻找粗粒度聚类后聚在一个簇中样本的未降维特征的下标
        #cluster_data是要进行细粒度聚类的Ci内部所有样本的特征集合
        for index in cluster_index:
            cluster_data.append(all_vec[index])
        xmeans = XMeans()
        cluster_data = np.array(cluster_data)
        xmeans.fit(cluster_data)
        #细粒度聚类对粗粒度聚类内部的点再进行一个裂
        mini_cluster_index = split_index(xmeans.labels_)
        #最后返回结果类似这种 [[ [2,3,4],  [6,5] ]    ]
        total_cluster_res.append(mini_cluster_index)
    print(total_cluster_res)
    return total_cluster_res
# def handle(root):
#     os.mkdir('res')
#     #device_list = ['360.camera','360_door_bell','aqara_gateway','biu_speaker','ezviz_camera','gree_gateway','gree_plug','hichip_battery_camera','honyar_outlet','ihorn_gateway','mercury_wirecamera','miai_soundbox','philips_camera','skyworth_camera','tcl_gateway','tcp_ddos','tmall_genie','tplink_camera','wiz_led','xiaodu_audio','xiaomi_camera','xiaomi_gateway','xiaomi_plug']
#     device_list = os.listdir(root)
#     print(device_list)
#     for i in device_list:
#         os.mkdir('res/' + i)
#         date_log_list = os.listdir('new_file/'+i)
#         for j in date_log_list:
#             all_vec,c_flow,c_fph,c_ppf,c_bpp,c_bps = read_pcap(root+'/'+i+'/'+j)
#             reduced_array = np.concatenate((c_fph,c_ppf,c_bpp,c_bps), axis=1)
#             all_vec = np.array(all_vec)
#             os.mkdir('res/'+i+'/'+j[:-5])
#             np.save('res/'+i+'/'+j[:-5]+'/1.npy',reduced_array,allow_pickle=True)
#             np.save('res/'+i+'/'+j[:-5]+'/2.npy',all_vec,allow_pickle=True)
# handle('./new_file')


def day_pcap_collect(device,days_num):
    root  = 'home/lry/data'
    day_pcap_list = os.listdir(root+'/'+device)
    for i in range(days_num):
        day_pcap_list[i] = root + '/'+device +'/'+day_pcap_list[i]
    print(day_pcap_list)
    return day_pcap_list[:days_num]
def device_run(device_name,days_num):
    file_list = day_pcap_collect(device_name,days_num)
    # all_vec, c_flow, c_fph, c_ppf, c_bpp, c_bps = np.array([]),np.array([]),np.array([]),np.array([]),np.array([]),np.array([])
    all_vec, c_flow, c_fph, c_ppf, c_bpp, c_bps = read_pcap(file_list[0])
    all_vec = np.array(all_vec)
    c_fph = np.array(c_fph)
    c_ppf = np.array(c_ppf)
    c_bpp = np.array(c_bpp)
    c_bps = np.array(c_bps)
    for pcap_file in file_list[1:days_num]:
        print(pcap_file)
        tmp_all_vec, tmp_c_flow, tmp_c_fph, tmp_c_ppf, tmp_c_bpp, tmp_c_bps = read_pcap(pcap_file)
        tmp_all_vec = np.array(tmp_all_vec)
        tmp_c_fph = np.array(tmp_c_fph)
        tmp_c_ppf = np.array(tmp_c_ppf)
        tmp_c_bpp = np.array(tmp_c_bpp)
        tmp_c_bps = np.array(tmp_c_bps)
        all_vec = np.concatenate((all_vec,tmp_all_vec),axis=0)
        c_flow.append(tmp_c_flow)
        c_fph = np.concatenate((c_fph,tmp_c_fph),axis=0)
        c_ppf = np.concatenate((c_ppf,tmp_c_ppf),axis=0)
        c_bpp = np.concatenate((c_bpp, tmp_c_bpp), axis=0)
        c_bps = np.concatenate((c_bps, tmp_c_bps), axis=0)
    cluster_indexes = cluster_1(c_fph,c_ppf,c_bpp,c_bps)
    total_cluster_res = cluster_2(cluster_indexes, all_vec)
    # home / lry / data / result.txt
    with open('result.txt','a') as f:
        f.write('----------Device name:--------------'+device_name+'------------------------------------------\n')
        f.write('1. result of first cluster stage: '+str(cluster_indexes)+'\n')
        f.write('2. result of second cluster stage:'+str(total_cluster_res)+'\n')
        f.write('\n')
    f.close()



# device_list = ['360_camera','360_door_bell','aqara_gateway','biu_speaker','ezviz_camera','gree_gateway','gree_plug','hichip_battery_camera','honyar_outlet','ihorn_gateway','mercury_wirecamera','miai_soundbox','philips_camera','skyworth_camera','tcl_gateway','tcp_ddos','tmall_genie','tplink_camera','wiz_led','xiaodu_audio','xiaomi_camera','xiaomi_gateway','xiaomi_plug']
# device_list = device_list[0:5]
# for device_name in device_list:
#     device_run(device_name,14)
# print(len(device_list))

def device_run_2(device_name,days_num):
    file_list = day_pcap_collect(device_name,days_num)
    # all_vec, c_flow, c_fph, c_ppf, c_bpp, c_bps = np.array([]),np.array([]),np.array([]),np.array([]),np.array([]),np.array([])
    all_vec, c_flow, c_fph, c_ppf, c_bpp, c_bps = read_pcap(file_list[0])
    all_vec = np.array(all_vec)
    c_fph = np.array(c_fph)
    c_ppf = np.array(c_ppf)
    c_bpp = np.array(c_bpp)
    c_bps = np.array(c_bps)
    for pcap_file in file_list[1:days_num]:
        print(pcap_file)
        tmp_all_vec, tmp_c_flow, tmp_c_fph, tmp_c_ppf, tmp_c_bpp, tmp_c_bps = read_pcap(pcap_file)
        tmp_all_vec = np.array(tmp_all_vec)
        tmp_c_fph = np.array(tmp_c_fph)
        tmp_c_ppf = np.array(tmp_c_ppf)
        tmp_c_bpp = np.array(tmp_c_bpp)
        tmp_c_bps = np.array(tmp_c_bps)
        all_vec = np.concatenate((all_vec,tmp_all_vec),axis=0)
        c_flow.append(tmp_c_flow)
        c_fph = np.concatenate((c_fph,tmp_c_fph),axis=0)
        c_ppf = np.concatenate((c_ppf,tmp_c_ppf),axis=0)
        c_bpp = np.concatenate((c_bpp, tmp_c_bpp), axis=0)
        c_bps = np.concatenate((c_bps, tmp_c_bps), axis=0)
    res = hierarchical_cluster(all_vec)
    # home / lry / data / result.txt
    with open('result.txt','a') as f:
        f.write('----------Device name:--------------'+device_name+'------------------------------------------\n')
        f.write('1. result of first cluster stage: '+str(res)+'\n')
        f.write('\n')
    f.close()

all_vec, c_flow, c_fph, c_ppf, c_bpp, c_bps = read_pcap('./new_file/2/2020-12-17.pcap')
all_vec = np.array(all_vec)
res1 = coarse_grained_cluster_and_evaluate(all_vec)
res2 = fine_grained_cluster(all_vec,res1)
print(res1)
print(res2)



# pcap_list = day_pcap_collect('files',7)
# all_vec,c_flow,c_fph,c_ppf,c_bpp,c_bps = read_pcap(pcap_list)
# print('all_vec:',all_vec)
# print('c_flow:',c_flow)
# print('c_fph',c_fph)
# print('c_ppf',c_ppf)
# print('c_bpp',c_bpp)
# print('c_bps',c_bps)
# # print('samples size before cluster:',np.array(all_vec).shape)
# indexes = cluster_1(c_fph,c_ppf,c_bpp,c_bps)
# res = cluster_2(indexes,all_vec)

#仍然存在的问题：TCP未完全建立的流（SYN,RST）的过滤，相同五元组流的断开（超出时间阈值的就分成两个流）
#聚类过程
#文件夹递归跑代码