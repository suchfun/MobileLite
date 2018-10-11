#!/usr/bin/python3
# _*_ coding:utf-8 _*_

import entropy
import numpy as np
import pandas as pd

# csv_path = 'permission.csv'          # permission.csv : The dataset from internet containing 199 malware and 199 benign APKs.
# df = pd.read_csv(csv_path,  sep=';')
data = []
'''
Load data that will be entered into Apriori algorithm

@return data:
    format:
    [
        ['android.permission.CALL_PHONE', 'android.permission.READ_SMS', 'android.permission.RECEIVE_SMS','android.permission.RESTART_PACKAGES', 'android.permission.SEND_SMS', 'android.permission.WRITE_APN_SETTINGS', 'android.permission.WRITE_CONTACTS'],
        ['android.permission.create_TASKS', 'android.permission.READ_SMS', 'android.permission.RECEIVE_MMS', 'android.permission.RECEIVE_SMS', 'android.permission.RECEIVE_WAP_PUSH', 'android.permission.SEND_SMS', 'android.permission.WRITE_APN_SETTINGS'],
    ]
'''
def load_data(df):
    entropy_permissions = entropy.entropy_select(df)
    df_apriori = df[entropy_permissions]                        # filter permissions we don't care

    for i in np.arange(df_apriori.index.__len__()):             # iterate all APKs
        entry = []
        row = df_apriori.ix[i]
        for j in np.arange(entropy_permissions.__len__()):      # in every APK, save the permissions the APK has
            if row[j]== 1:
                entry.append(entropy_permissions[j])
        if entry.__len__() > 0:
            data.append(entry)
    # with open('E:\Desktop\data_apriori.txt','a') as fw:
    #     fw.write(data.__str__())

# create candidate frequente 1-itemset
def __create_C1():
    C1 = []
    for trans in data:
        for item in trans:
            if not(C1.__contains__(item)):
                C1.append(item)
    return C1

'''
Create frequente 1-itemset

@return F1 :
    ex:
    ['android.permission.CALL_PHONE', 'android.permission.READ_SMS', 'android.permission.RECEIVE_SMS']
@return F1_supoort :
    ex:
    {'android.permission.CALL_PHONE' : 0.9, 
    'android.permission.READ_SMS' : 0.8, 
    'android.permission.RECEIVE_SMS' : 0.88}
'''
def __create_F1(min_support):
    C1 = __create_C1()
    trans_num = len(data)
    F1_supprot = {}
    for item in C1:
        item_num = 0                            # how many transaction contains the item
        for i in np.arange(trans_num):
            if item in data[i]:
                item_num = item_num + 1
        item_support = item_num/trans_num       # if item_support > min_support,save it to F1_support
        if item_support >= min_support:
            F1_supprot[item] = item_support
    F1 = list(F1_supprot.keys())
    return F1,F1_supprot

# create condidate frequente 2-itemset by frequente 1-itemset
def __create_C2_by_F1(F1):
    C2 = []
    for i in np.arange(len(F1)):
        for j  in np.arange(i+1,len(F1)):
            C2.append([F1[i],F1[j]])
    return C2

'''
Create frequente 2-itemset 

@return F2 :
    [frozenset({'android.permission.READ_SMS', 'android.permission.CALL_PHONE'}), frozenset({'android.permission.RECEIVE_SMS', 'android.permission.CALL_PHONE'})] 
@return F2_support :
    {frozenset({'android.permission.READ_SMS', 'android.permission.CALL_PHONE'}): 0.2619047619047619, 
    frozenset({'android.permission.RECEIVE_SMS', 'android.permission.CALL_PHONE'}): 0.23333333333333334}
'''
def __create_F2(F1,min_support):
    C2 = __create_C2_by_F1(F1)
    trans_num = len(data)
    F2_support = {}
    for item in C2:
        item_num = 0
        for i in np.arange(len(data)):
            if item[0] in data[i] and item[1] in data[i]:
                item_num = item_num + 1
        item_support = item_num/trans_num
        if item_support >= min_support:
            F2_support[frozenset(item)] = item_support
    F2 = list(F2_support.keys())
    return F2,F2_support

'''
Find all mutual strong 2-items connetction

ex:
A=>B with confidence >= min_confidence
AND
B=>A with confidence >= min_confidence
'''
def __mutual_strong_connection(F1_support,F2_support,min_confidence):
    connection = []
    for item in F2_support:
        count = 0
        for it in item :
            if F2_support[item]/F1_support[it] >= min_confidence:
                count = count + 1
        if count == 2:
            connection.append(item)
    return connection

# delete one permission of mutual strong 2-items connection
def __del_strong_connection(F1,connection):
    F1_del = F1.copy()
    for item in connection:
        for it in item:
            F1_del.remove(it)
            break
    return F1_del

'''
Select permissions through Apriori select

@param  min_support :
    Minimum support guarantees that the permission is used by at least a certain number of APKs.
@param min_confidence :
    Minimum confidence guarantees the degree to which the association rules are trusted.
'''
def apriori_select(df,*,min_support,min_confidence):
    load_data(df)
    F1,F1_support = __create_F1(min_support)
    F2,F2_support = __create_F2(F1,min_support)

    connection = __mutual_strong_connection(F1_support,F2_support,min_confidence)
    F1_del = __del_strong_connection(F1,connection)

    # print('Matual Strong Connection:')
    # print(connection)

    print('After Apriori Select,These Permissions Are Kept:')
    for i in np.arange(F1_del.__len__()):
        print(F1_del[i])
    print('A Total Of '+F1_del.__len__().__str__()+' Permissions.')
    return F1_del

# test
# if __name__ == "__main__":
#     prmissions = apriori_select(min_support=0.2,min_confidence=0.8)