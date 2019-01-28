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
import APK_Method_Key_Words
print(dvm_types.TYPE_DESCRIPTOR['I'])
'''
该脚本的功能是将所有初始的apk进行提取回调函数，然后用于后期建立语料库所用
'''
#用于获取所有的回调函数
reader=csv.reader(open('F:\\2018年第一学年科研\\APK科研\\数据集\\callback_api.csv'))
all_callback=set()
for i in reader:
    all_callback.add(i[1])
print(len(all_callback))
#此函数用于获取一个方法的所有word
def Get_Word(method):
    method_final=[]
    method = method.replace(')',';Rbracket;')
    method = method.replace('(', ';Lbracket;')
    method = method.replace('[', 'array;')
    method=re.split('[//;== /''\.]',method)
    for k in method:
        if k !='':
            if k in['V','Z','B','S', 'C','I','J','F','D']:
                method_final.append(dvm_types.TYPE_DESCRIPTOR[k])
            else:
                method_final.append(k)
    # print(len(method_final))
    return method_final
    #   此函数的功能是将一个apk的源代码写到本地
#用于将一个apk的源码写在本地,进行源码的分析
def write_one_apk_source(apkfile):
    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    a1, d1, dx = AnalyzeAPK(apkfile)
    CFG = nx.DiGraph()
    with open('F:\\2018年第一学年科研\\APK科研\\数据集\\Word2vec_ao_yuliaoku\\test\\successed_1.txt', 'w') as txtData:
        for k in d.get_classes():
            print('class_name:' + k.get_name())
            txtData.writelines(dp.get_source_class(k))
            for m in dx.find_methods(classname=k.get_name()):
                orig_method = m.get_method()
                if isinstance(orig_method, ExternalMethod):
                    is_this_external = True
                else:
                    is_this_external = False
                CFG.add_node(orig_method, external=is_this_external)
                if is_this_external == False:  # 用于获取一个class里面的所有方法
                    print('orig::' + orig_method.get_name())
                else:
                    print('orig+external::'+orig_method.get_name())
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
    #  此函数的功能是用于处理一个apk
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
            else:
                print('orig+externalmethod::'+orig_method.get_name())
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
    class_code_dic,is_amd_class_code_dic=Update_one_apk_dictory(apkfile)
    for k in d.get_classes():
        amd_p1='Lmy/app/client/Client;'
        if k.get_name()== amd_p1:
            # print(dp.get_source_class(k))
            all_orig_methods = []
            for m in dx.find_methods(classname=amd_p1):#用于将一个class里面所有的原始方法提取到
                orig_method = m.get_method()
                if isinstance(orig_method, ExternalMethod):
                    is_this_external = True
                else:
                    is_this_external = False
                CFG.add_node(orig_method, external=is_this_external)
                if not isinstance(orig_method, ExternalMethod):
                    all_orig_methods.append(orig_method)
            for m in dx.find_methods(classname=amd_p1):#用于遍历一个class里面的所有的方法
                orig_method = m.get_method()
                if not isinstance(orig_method, ExternalMethod):
                    if (orig_method.get_name() in all_callback) or (orig_method.get_name() in APK_Method_Key_Words.key_registers):
                        callees = []  # 用于将所有的不在这个class里面的函数保存下来
                        for other_class, callee, offset in m.get_xref_to():
                            if isinstance(callee, ExternalMethod):
                                is_external = True
                            else:
                                is_external = False
                            if callee not in CFG.node:
                                CFG.add_node(callee, external=is_external)
                                callees.append(callee)
                        for callee in callees:
                            if callee in all_orig_methods:
                                class_code_dic[k.get_name()][orig_method.get_name()+orig_method.get_descriptor()]+=class_code_dic[k.get_name()][callee.get_name()+callee.get_descriptor()]
                        print(class_code_dic[k.get_name()][orig_method.get_name()+orig_method.get_descriptor()])
                        print(is_amd_class_code_dic[k.get_name()][orig_method.get_name()+orig_method.get_descriptor()])

    return apk_word
#用于建立APK语料库
def Build_APK_Corpus(apkfile):
    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    a1, d1, dx = AnalyzeAPK(apkfile)
    CFG = nx.DiGraph()
    class_code_dic, is_amd_class_code_dic = Update_one_apk_dictory(apkfile)
    for k in d.get_classes():
        all_orig_methods = []#用于统计所有的原始的方法
        for m in dx.find_methods(classname=k.get_name()):  # 用于将一个class里面所有的原始方法提取到
            orig_method = m.get_method()
            if isinstance(orig_method, ExternalMethod):
                is_this_external = True
            else:
                is_this_external = False
            CFG.add_node(orig_method, external=is_this_external)
            if not isinstance(orig_method, ExternalMethod):
                all_orig_methods.append(orig_method)
        for m in dx.find_methods(classname=k.get_name()):  # 用于遍历一个class里面的所有的方法
            orig_method = m.get_method()
            if not isinstance(orig_method, ExternalMethod):
                if (orig_method.get_name() in all_callback) or (
                        orig_method.get_name() in APK_Method_Key_Words.key_registers):
                    callees = []  # 用于将所有的不在这个class里面的函数保存下来
                    for other_class, callee, offset in m.get_xref_to():
                        if isinstance(callee, ExternalMethod):
                            is_external = True
                        else:
                            is_external = False
                        if callee not in CFG.node:
                            CFG.add_node(callee, external=is_external)
                            callees.append(callee)
                    for callee in callees:
                        if callee in all_orig_methods:
                            class_code_dic[k.get_name()][orig_method.get_name() + orig_method.get_descriptor()] += \
                                class_code_dic[k.get_name()][callee.get_name() + callee.get_descriptor()]
                            if callee.get_class_name() in is_amd_class_code_dic.keys():
                                if is_amd_class_code_dic[k.get_name()][callee.get_name()+callee.get_descriptor()]=='true':
                                    is_amd_class_code_dic[k.get_name()][orig_method.get_name()+orig_method.get_descriptor()]='true'
                    # print(class_code_dic[k.get_name()][orig_method.get_name() + orig_method.get_descriptor()])
                    # print(is_amd_class_code_dic[k.get_name()][orig_method.get_name() + orig_method.get_descriptor()])
    return class_code_dic,is_amd_class_code_dic
#用于获取初始的apk字典,并且用于后面的更新
def Get_one_apk_dictory(apkfile):
    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    a1, d1, dx = AnalyzeAPK(apkfile)
    CFG = nx.DiGraph()
    class_code_dic = {}  # 用于将class里面的所有关键的代码保存下来
    # 其格式为 class_code_dic={'class1':'key_class1','class2':'key_class2'}
    is_amd_class_code_dic = {}#用于将class里面的所有method里面是否含有amd数据保存下来
    for k in d.get_classes():
        method_dic = {}  # 用于将一个方法里面的所有关键代码保存下来,其形式是method_dic={'method1':'key_word1','method2':'....}
        is_amd_method_dic = {}
        # print('class_name:' + k.get_name())
        # print(dp.get_source_class(k))
        for m in dx.find_methods(classname=k.get_name()):
            orig_method = m.get_method()
            if isinstance(orig_method, ExternalMethod):#将原始结点保存在CFG中
                is_this_external = True
            else:
                is_this_external = False
            CFG.add_node(orig_method, external=is_this_external)
            callees = []  # 用于将所有的不在这个class里面的函数保存下来
            for other_class, callee, offset in m.get_xref_to():
                if isinstance(callee, ExternalMethod):
                    is_external = True
                else:
                    is_external = False
                if callee not in CFG.node:#将非原始结点，即外部的结点保存在CFG中
                    CFG.add_node(callee, external=is_external)
                    callees.append(callee)
            orig_method_code = []
            orig_method_key_words = []
            if not isinstance(orig_method, ExternalMethod):  # 用于将这个class创建的所有函数获取到
                orig_method_code = orig_method.get_source().split('\n')
                orig_method_code = [i.strip() for i in orig_method_code]
                orig_method_key_words+=Get_Word(orig_method.get_name() + '==' + orig_method.get_descriptor())
                for callee in callees:
                    if not isinstance(callee, ExternalMethod):
                        if callee.get_name() != orig_method.get_name():
                            callee_code = callee.get_source().split('\n')
                            callee_code = [i.strip() for i in callee_code]
                            orig_method_code += callee_code  # 得到一个method的内部的所有的源代码
                            orig_method_key_words+=Get_Word(callee.get_name() + '==' + callee.get_descriptor())
            if not isinstance(orig_method, ExternalMethod):  # 如果在一个class里面的method是非外部方法，则提取其内部代码
                amd_num = 0  # 用于统计这个method是否是包含amd的method
                # --------------用于判断amd数据---------------
                for key in APK_Method_Key_Words.amd_key_words:
                    for code in orig_method_code:  # 得到一个method内部的所有的源码
                        if key in code:
                            amd_num += 1
                            orig_method_key_words+=Get_Word(key)
                #  ----------用于判断intent代理机制-------------
                for key in APK_Method_Key_Words.key_Intent:
                    for code in orig_method_code:  # 得到一个method内部的所有的源码
                        if key in code:
                            key_word = Get_Word(key)
                            key_word.append('Rbracket')
                            orig_method_key_words+=key_word
                if amd_num > 0:
                    #  用于判断此函数里面是否含有恶意代码
                    is_amd_method_dic[orig_method.get_name() + orig_method.get_descriptor()] = 'true'
                else:
                    is_amd_method_dic[orig_method.get_name() + orig_method.get_descriptor()] = 'false'
                method_dic[orig_method.get_name() + orig_method.get_descriptor()] = orig_method_key_words
        class_code_dic[k.get_name()] = method_dic  # 用于将一个class里面的所有关键代码保存下来
        is_amd_class_code_dic[k.get_name()] = is_amd_method_dic
    # print(is_amd_class_code_dic)
    # print(class_code_dic)
    #用于将俩个字典返回，目的是为了进行后面的工作
    return class_code_dic,is_amd_class_code_dic
#用于更新一圈的apk的字典，得到最后的apk字典
def Update_one_apk_dictory(apkfile):
    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    a1, d1, dx = AnalyzeAPK(apkfile)
    CFG = nx.DiGraph()
    class_code_dic, is_amd_class_code_dic = Get_one_apk_dictory(apkfile)
    for k in d.get_classes():
        if k.get_name() == k.get_name():
            for m in dx.find_methods(classname=k.get_name()):  # 用于遍历一个class里面的所有的方法
                orig_method = m.get_method()
                if isinstance(orig_method, ExternalMethod):
                    is_this_external = True
                else:
                    is_this_external = False
                CFG.add_node(orig_method, external=is_this_external)#将原始结点保存在CFG中
                callees = []  # 用于将所有的不在这个class里面的函数保存下来
                for other_class, callee, offset in m.get_xref_to():
                    if isinstance(callee, ExternalMethod):
                        is_external = True
                    else:
                        is_external = False
                    if callee not in CFG.node:
                        CFG.add_node(callee, external=is_external)#将不在此method的所有的函数保存在CFG中
                        callees.append(callee)
                '----------提出一个问题-----对于一个class里面的函数调用另外一个class里面的函数'
                orig_method_key_words = []
                if not isinstance(orig_method, ExternalMethod):  # 用于将属于这个class的所有method提取出来
                    b = 'false'
                    orig_method_key_words += (class_code_dic[k.get_name()][orig_method.get_name()+orig_method.get_descriptor()])
                    for callee in callees:  # 用于统计非该class里面的函数,并且更新origin函数的所有关键字
                        if callee.get_class_name() in class_code_dic.keys():
                            # 如果函数在字典里面，则将其关键字提取出来
                            if (callee.get_name() + callee.get_descriptor()) in class_code_dic[callee.get_class_name()].keys():

                                orig_method_key_words += class_code_dic[callee.get_class_name()][callee.get_name() + callee.get_descriptor()]

                                if is_amd_class_code_dic[callee.get_class_name()][callee.get_name()+callee.get_descriptor()]=='true':
                                   b='true'
                                else:
                                    pass
                            else:
                                orig_method_key_words += (Get_Word(callee.get_name() + callee.get_descriptor()))

                    # -------用于更新一下原始函数的key值
                    class_code_dic[k.get_name()][orig_method.get_name() + orig_method.get_descriptor()] = orig_method_key_words
                    if b=='true':
                        is_amd_class_code_dic[k.get_name()][orig_method.get_name()+orig_method.get_descriptor()]='true'

    return class_code_dic,is_amd_class_code_dic
#用于读取amd数据集
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
#用于处理amd数据集
def Deal_all_amd_data():
    path = "F:\\2018年第一学年科研\\APK科研\\数据集\\amd_data\\AndroRAT\\variety1\\a537253264aae9dd0fc41105a5f02d51.apk"
    # all_amd_path = Read_amd_data(path)
    # # for path in range(len(all_amd_path)):
    # #     print(all_amd_path[path])
    # print(all_amd_path)
    # Deal_one_apk(path)
    Build_APK_Corpus(path)
    # write_one_apk_source(path)
#用于处理非AMD数据集
def Deal_all_data():
    path='F:\\2018年第一学年科研\\APK科研\\数据集\\seprated_apks\\entertainment_succeed\\br.com.frs.foodrestrictions_2.apk'
    Deal_one_apk(path)
    # write_one_apk_source(path)
if __name__ == "__main__":
    Deal_all_amd_data()
    # Deal_all_data()