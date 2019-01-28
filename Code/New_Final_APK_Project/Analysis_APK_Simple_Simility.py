import csv
from androguard.misc import AnalyzeAPK
from androguard.core.analysis.analysis import ExternalMethod
import matplotlib.pyplot as plt
import networkx as nx
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.decompiler import decompiler
from androguard.core.bytecodes import dvm_types#这个里面包含了所有的类型定义和返回类型定义
import re
import os
from APK_Method_Analysis import *

def Get_Apk_Source_Code(apkfile):

    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    #用于获取源码
    with open('F:\\2018年第一学年科研\\APK科研\\数据集\\Word2vec_ao_yuliaoku\\source.txt', 'w')as txtfile:
        for k in d.get_classes():  # 对于每一个class
            # print(dp.get_source_class(k))
            txtfile.writelines(dp.get_source_class(k))

def Get_APK_Words(apkfile):
    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    a1, d1, dx = AnalyzeAPK(apkfile)
    CFG = nx.DiGraph()
    class_code_dic, is_amd_class_code_dic = Build_APK_Corpus(apkfile)
    for k in d.get_classes():  # 用于遍历每一个class
        all_orig_methods = []  # 用于统计一个class里面的所有的method
        # print(type(k))
        print('class_name+super_name::'+k.get_name()+':'+k.get_superclassname())
        for m in dx.find_methods(classname=k.get_name()):  # 用于将一个class里面所有的原始方法提取到
            orig_method = m.get_method()
            if isinstance(orig_method, ExternalMethod):
                is_this_external = True
            else:
                is_this_external = False
            CFG.add_node(orig_method, external=is_this_external)
            if not isinstance(orig_method, ExternalMethod):
                all_orig_methods.append(orig_method)  # 用于得到所有的原始方法
        for m in dx.find_methods(classname=k.get_name()):  # 用于遍历一个class里面的所有的方法
            orig_method = m.get_method()
            if not isinstance(orig_method, ExternalMethod):
                if (orig_method.get_name() in all_callback) or (
                        orig_method.get_name() in APK_Method_Key_Words.key_registers):
                    print('method_name+method_descriptor::'+orig_method.get_name()+orig_method.get_descriptor())
                    print(class_code_dic[k.get_name()][orig_method.get_name() + orig_method.get_descriptor()])
def Get_DataSet():
    path='F:\\2018年第一学年科研\\APK科研\数据集\\amd_data\\DroidKungFu\\variety1\\1d908963aa08e265190817f88bb3ae3c.apk'
    path1='F:\\2018年第一学年科研\\APK科研\\数据集\\seprated_apks\\entertainment_succeed\\com.github.redpanal.android_2.apk'
    print(path)
    Get_APK_Words(path)
    Get_Apk_Source_Code(path)
if __name__ == "__main__":
    Get_DataSet()