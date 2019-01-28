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
print(dvm_types.TYPE_DESCRIPTOR['I'])
#用于获取所有的回调函数
reader=csv.reader(open('F:\\2018年第一学年科研\\APK科研\\数据集\\callback_api.csv'))
all_callback=set()
for i in reader:
    all_callback.add(i[1])
print(len(all_callback))
def Deal_Method(method):
    method_final=[]
    method = method.replace(')',';Rbracket;')
    method = method.replace('(', ';Lbracket;')
    method = method.replace('[', 'array;')
    method=re.split('[//;==]',method)
    for k in method:
        if k !='':
            if k in['V','Z','B','S', 'C','I','J','F','D']:
                method_final.append(dvm_types.TYPE_DESCRIPTOR[k])
            else:
                method_final.append(k)
    print(method_final)
    return method_final
def Get_Word(method):
    method_final=[]
    method = method.replace(')',';Rbracket;')
    method = method.replace('(', ';Lbracket;')
    method = method.replace('[', 'array;')
    method=re.split('[//;== /'']',method)
    for k in method:
        if k !='':
            if k in['V','Z','B','S', 'C','I','J','F','D']:
                method_final.append(dvm_types.TYPE_DESCRIPTOR[k])
            else:
                method_final.append(k)
    return method_final
def write_one_apk_source(apkfile):
    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    a1, d1, dx = AnalyzeAPK(apkfile)
    CFG = nx.DiGraph()
    apk_word = []
    with open('F:\\2018年第一学年科研\\APK科研\\数据集\\Word2vec_ao_yuliaoku\\test\\successed_1.txt', 'w') as txtData:
        for k in d.get_classes():
            print('class_name:' + k.get_name())
            # print(dp.get_source_class(k))
            txtData.writelines(dp.get_source_class(k))
            for m in dx.find_methods(classname=k.get_name()):
                orig_method = m.get_method()
                # print(type(orig_method))
                if isinstance(orig_method, ExternalMethod):
                    is_this_external = True
                else:
                    is_this_external = False
                CFG.add_node(orig_method, external=is_this_external)
                if is_this_external == False:  # 用于获取一个class里面的所有方法
                    print('orig::' + orig_method.get_name())
                    # if orig_method.get_name() in all_callback:
                    #     print('orig::' + orig_method.get_name())
                else:
                    # if orig_method.get_name() in all_callback:
                    print('orig+external::'+orig_method.get_name())
                    # txtData.write('orig::' + orig_method.get_name())
                for other_class, callee, offset in m.get_xref_to():
                    if isinstance(callee, ExternalMethod):
                        is_external = True
                    else:
                        is_external = False
                    if callee not in CFG.node:
                        CFG.add_node(callee, external=is_external)
                        if is_external == False:
                            print('external+callee::' + callee.get_name())
                            # if callee.get_name() in all_callback:
                            #     print('external+callee::' + callee.get_name())
                            # txtData.write('external+callee::' + callee.get_name())
                        else:
                            print('callee:' + callee.get_name())
                            # if callee.get_name() in all_callback:
                            #     print('callee:' + callee.get_name())
                            # txtData.write('callee:' + callee.get_name())
def Deal_one_apk_new(apkfile):
    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    a1, d1, dx = AnalyzeAPK(apkfile)
    CFG = nx.DiGraph()
    apk_word = []
    for k in d.get_classes():
        print('class_name:' + k.get_name())
        # print(dp.get_source_class(k))
        for m in dx.find_methods(classname=k.get_name()):
            orig_method = m.get_method()
            # print(type(orig_method))
            if isinstance(orig_method, ExternalMethod):
                is_this_external = True
            else:
                is_this_external = False
            CFG.add_node(orig_method, external=is_this_external)
            if is_this_external == False:  # 用于获取一个class里面的所有方法
                print('orig::' + orig_method.get_name())
            for other_class, callee, offset in m.get_xref_to():
                if isinstance(callee, ExternalMethod):
                    is_external = True
                else:
                    is_external = False
                if callee not in CFG.node:
                    CFG.add_node(callee, external=is_external)
                    if is_external == False:
                        print('external+callee::' + callee.get_name())
                    else:
                        print('callee:' + callee.get_name())


def Deal_one_apk(apkfile):
    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    a1, d1, dx = AnalyzeAPK(apkfile)
    CFG = nx.DiGraph()
    apk_word = []
    for k in d.get_classes():
        # print('class_name:'+k.get_name())
        amd_p1='Lcom/mix_four/dd/LockReceiver;'
        amd_p2='Lcom/mix_four/dd/CoreService$MyOrderRunnable;'
        amd_p3='Landroid/support/v4/content/IntentCompat$IntentCompatImplBase;'
        amd_p4='Lcom/mix_four/dd/CoreService$MyOrderRunnable;'
        if k.get_name()== amd_p1:
            print('class_name:' + k.get_name())
            print(dp.get_source_class(k))
            for m in dx.find_methods(classname=amd_p1):
                orig_method = m.get_method()
                if isinstance(orig_method, ExternalMethod):
                    is_this_external = True
                else:
                    is_this_external = False
                CFG.add_node(orig_method, external=is_this_external)
                if is_this_external == False:  # 用于获取一个class里面的所有方法
                    print('orig::' + orig_method.get_name())
                for other_class, callee, offset in m.get_xref_to():
                    if isinstance(callee, ExternalMethod):
                        is_external = True
                    else:
                        is_external = False
                    if callee not in CFG.node:
                        CFG.add_node(callee, external=is_external)
                        if is_external == False:
                            print('external+callee::' + callee.get_name())
                        else:
                            print('callee:' + callee.get_name())
    return apk_word
def Read_amd_data(path):#用于读取amd_data
    allFiles = []
    if os.path.isdir(path):
        fileList = os.listdir(path)
        for f in fileList:
            f = path + '\\' + f
            if os.path.isdir(f):
                subFiles = Read_amd_data(f)
                allFiles = subFiles + allFiles  # 合并当前目录与子目录的所有文件路径
            else:
                allFiles.append(f)
        return allFiles
    else:
        return 'Error,not a dir'
def Deal_all_amd_data():
    path = "F:\\2018年第一学年科研\\APK科研\\数据集\\amd_data\\FakeAngry\\variety1\\39918f43de3e1d2320c5741e61da9e90.apk"
    # all_amd_path = Read_amd_data(path)
    # # for path in range(len(all_amd_path)):
    # #     print(all_amd_path[path])
    # print(all_amd_path)
    # Deal_one_apk(path)
    write_one_apk_source(path)
def Deal_all_data():
    path='F:\\2018年第一学年科研\\APK科研\\数据集\\seprated_apks\\entertainment_succeed\\br.com.frs.foodrestrictions_2.apk'
    # Deal_one_apk_new(path)
    write_one_apk_source(path)
if __name__ == "__main__":
    # Deal_all_amd_data()
    Deal_all_data()