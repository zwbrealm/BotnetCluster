from datetime import datetime
import numpy as np
from sklearn.decomposition import PCA
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics import davies_bouldin_score as dbs
from scipy.spatial.distance import pdist

def time_convert(time):
    hour = datetime.fromtimestamp(time + 43200).strftime('%H')
    return int(hour)
#判断是否存在有“相同”的流,否则进行合并处理
def compare_and_merge(flow_list,a):
    # 返回那个匹配上的C—flow对象
    #满足IP相同，源端口不同的这种情况
    #或者对于五元组完全相同，但有中断的情况，也采取合并措施
    for i in flow_list:
        if i.five_tuple[0] == a.five_tuple[0] and i.five_tuple[2] == a.five_tuple[2] and i.five_tuple[3] == a.five_tuple[3] and i.five_tuple[4] == a.five_tuple[4]:
            i.cnt.append(a.cnt)
            i.bytes.append(a.bytes)
            i.time_seq.append(a.time_seq)
            return True
def check_interval(a,b):
    if b - a < 0.4:
        return True
    return False


def find_tuple_and_update(flow_list,a,time,bytes):
    #找到五元组完全匹配的流对象
    for i in flow_list:
        if i.five_tuple == a:
            prev_time = i.time_seq[-1]
            if check_interval(prev_time,time):
                i.set_bytes(bytes)
                i.set_cnt(1)
                i.time_add(time)
                return True
    #由于没有匹配的五元组或者有匹配的五元组但时间间隔偏大，返回False，自己单独成为一个fi对象
    return False


#计算分位数,分为5个等级,并输出每个区间内值的个数
def cut(list,level):
    res = [0]*level
    max_value = max(list)
    min_value = min(list)
    list.sort()
    #区间的list
    bound = np.linspace(min_value,max_value,level)
    # bound = [bound[0],bound[5],bound[10],bound[3],bound[10],bound[999]]
    #初始化指针
    bound_start = 1
    # print(bound)
    #寻找落在此范围内的值
    for i in list:
        while(i>bound[bound_start]):
            bound_start += 1
        #落在此范围内的值+1
        res[bound_start - 1] += 1
    return res

#降维，每个特征的n维降到只有2维
def sqeenze(x):
    x = np.array(x)
    pca = PCA(n_components=2)
    reduced_data = pca.fit_transform(x)
    return reduced_data
#cluster第一阶段，将label不同的分开
def split_index(x):
    #去重后并从小到大排序的label列表
    unique_list = list(set(x))
    cluster_index = []
    unique_list.sort()
    #考虑整个数列均相等的问题
    if unique_list[0] == unique_list[-1]:
        cluster_index.append(range(0, len(unique_list)))
        return cluster_index
    #label 从 0 - N各类的index进行合并

    for value in unique_list:
        tmp_indexset = [i for i, y in enumerate(x) if y == value]
        cluster_index.append(tmp_indexset)
    return cluster_index

def coarse_grained_cluster_and_evaluate(data):
    #单链接层次聚类
    scores = []
    labels = []
    for k in range(2,min(data.shape[0],15)):
        sk = AgglomerativeClustering(linkage ='single',n_clusters=k,affinity ='euclidean')
        label = sk.fit_predict(data)
        score = dbs(data, label)
        scores.append(score)
        labels.append(label)

    min_index = scores.index(min(scores))
    best_result = labels[min_index]
    res = split_index(best_result)
    #返回聚类结果
    return res


def fine_grained_cluster(data,index_cluster,threshold):
    fine_grained_cluster_res = []
    # print(index_cluster)

    for cluster in index_cluster:
        tmp = []
        for i in cluster:
            tmp.append(data[i])
        #设置阈值，
        tmp = np.array(tmp)
        if tmp.shape[0] == 1:
            fine_grained_cluster_res.append([0])
            continue
        # 如果其直径大于某个界限才分裂，否则不分裂
        dist = pdist(tmp, metric='euclidean')
        # 在这种情况下不分裂，直接返回
        if max(dist) <= threshold:
            l = list(range(0,len(cluster)))
            fine_grained_cluster_res.append(l)
            continue
        # 如果样本数目过少，那就大于某个阈值才分
        if tmp.shape[0] == 2:
            fine_grained_cluster_res.append([0,1])
            continue
        #大于阈值，而且个数大于等于3
        scores = []
        labels = []

        for k in range(2,len(tmp)):
            sk = AgglomerativeClustering(n_clusters = k,linkage='single',affinity='euclidean')
            label = sk.fit_predict(tmp)
            # print('-------------------'+str(len(label))+'------------------------')
            # if min(label) == max(label):
            # print('--------------------'+str(label)+'-------------------------------')
            score = dbs(tmp, label)
            scores.append(score)
            labels.append(label)
        # print(scores)
        min_index = scores.index(min(scores))
        best_result = labels[min_index]
        res = split_index(best_result)
        fine_grained_cluster_res.append(res)
    return fine_grained_cluster_res
# def evaluate_cluster