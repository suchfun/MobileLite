#!/usr/bin/python3
# _*_ coding:utf-8 _*_

import pandas as pd
import numpy as np

'''
# test
csv_path = 'E:\Desktop\permission.csv'          # permission.csv : The dataset from internet containing 199 malware and 199 benign APKs.
df = pd.read_csv(csv_path,  sep=';')
'''
txt_path = 'permission.txt'          # permission.txt : All system permissions obtained from the official website

'''
Calculate entropy by probability

@param  x :
    The probability that an APK containing the permission is malware.(0<=x<=1)
@return ent :
    Entropy corresponding to probability
'''
def __cal_entropy(x):
    if x == 1 or x == 0:
        ent = 0
    else:
        ent = -1 * (x * np.log2(x) + (1 - x) * np.log2(1 - x))
    return ent

'''
Put all system permissions declared by official website in a list and return
'''
def __android_permissions():
    permissions = []
    with open(txt_path,'r') as f:
        line = f.readline()
        while line:
            permissions.append(line.replace('\n',''))
            line = f.readline()
    return permissions

'''
Calculate entropy of the permission in dataset

If the entropy of this permission is small, 
it means that dividing the dataset with this permission makes the dataset more 'PURE'.

Entropy formula : 
    Ent(j) = -1*(pj*logpj+(1-pj)log(1-pj))
@param df : 
    DataFrame of 'permission.csv'.
@param permission : 
    The permission you wanna calculate.
@return ent : 
    Entropy of the permission.(0<entrpy<1),
    if return value is -1,it means the permission not used in malware and benign APKs.
'''
def __entropy(df,permission):
    permission_num = df[permission].sum()
    num_APKs = df.index.__len__()
    if permission_num > 0:          # elimilate the permission not used in malware and benign APKs
        num_in_malware = 0
        for i in np.arange(num_APKs):
            if df[permission][i] == 1 and df['type'][i] == 1:
                num_in_malware = num_in_malware+1
        p_permission = num_in_malware/permission_num
        ent = __cal_entropy(p_permission)
    else:
        ent = -1
    return ent

'''
Select permissions of entropy meet threshold set by customer

Reference:
    |   p   |   E   |
    -----------------
    |   0   |   0   |
    -----------------
    |   1   |   0   |
    -----------------
    |  0.5  |   1   |
    -----------------
    |  0.81 |   0.7 |
    -----------------
    |  0.85 |   0.6 |
    -----------------
    |  0.89 |   0.5 |
@param  df:
    DataFrame of 'permission.csv'.
@param  threshold:
    We choose the permission which's entropy is less than threshold.
@return prmissions:
    Return permissions through entropy select.
'''
def entropy_select(df,*,threshold=0.5):
    permissions = []
    official_permission = __android_permissions()
    num_permissions = df.columns.__len__()-1        # remove the last column 'type'
    for i in np.arange(num_permissions):
        if df.columns[i] in official_permission:
            ent = __entropy(df, df.columns[i])
            if ent != -1 and ent < threshold:
                permissions.append(df.columns[i])
    # print permissions through entropy select
    print('After Entropy Select,These Permissions Are Kept :')
    for i in np.arange(permissions.__len__()):
        print(permissions[i])
    print('A Total Of '+permissions.__len__().__str__()+' Permissions.')
    return permissions

# test
#entropy_select(df)