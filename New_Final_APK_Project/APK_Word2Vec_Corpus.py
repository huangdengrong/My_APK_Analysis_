from APK_Method_Analysis import *
'该脚本的功能是用于进行建立语料库，将所有的word保存到本地，然后进行后期词向量的转换'
def Bulid_Corpus(apkfile,writer):
    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    a1, d1, dx = AnalyzeAPK(apkfile)
    CFG = nx.DiGraph()
    class_code_dic, is_amd_class_code_dic = Build_APK_Corpus(apkfile)
    '-------------用于进行建立预料库，将所有的语料库保存到本地---------------------'
    for k in d.get_classes():  # 用于遍历每一个class
        class_all_words = Get_Class_Word(k, CFG, dx, class_code_dic)
        if class_all_words != []:
            print(k.get_name())
            # print(len(class_all_words))
            writer.writerow(class_all_words)

def Get_Method_Word(method_,class_,class_all_words,class_code_dic):
    method_words=[]
    orig_method = method_.get_method()
    if not isinstance(orig_method, ExternalMethod):
        if (orig_method.get_name() in all_callback) or (
                orig_method.get_name() in APK_Method_Key_Words.key_registers):  # 提取回调函数序列
            class_all_words += class_code_dic[class_.get_name()][orig_method.get_name() + orig_method.get_descriptor()]
            method_words+=class_code_dic[class_.get_name()][orig_method.get_name() + orig_method.get_descriptor()]
    return class_all_words,class_code_dic,method_words
#此函数用于获取一个class里面的所有的Word
def Get_Class_Word(class_,CFG,dx,class_code_dic):
    all_orig_methods = []  # 用于统计一个class里面的所有的method
    class_all_words = []  # 用于统计一个class里面的所有的word
    for m in dx.find_methods(classname=class_.get_name()):  # 用于将一个class里面所有的原始方法提取到
        orig_method = m.get_method()
        if isinstance(orig_method, ExternalMethod):
            is_this_external = True
        else:
            is_this_external = False
        CFG.add_node(orig_method, external=is_this_external)
        if not isinstance(orig_method, ExternalMethod):
            all_orig_methods.append(orig_method)  # 用于得到所有的原始方法
    for m in dx.find_methods(classname=class_.get_name()):  # 用于遍历一个class里面的所有的方法
        orig_method = m.get_method()
        if not isinstance(orig_method, ExternalMethod):
            if (orig_method.get_name() in all_callback) or (
                    orig_method.get_name() in APK_Method_Key_Words.key_registers):  # 提取回调函数序列
                # print(class_code_dic[k.get_name()][orig_method.get_name()+orig_method.get_descriptor()])
                class_all_words += class_code_dic[class_.get_name()][orig_method.get_name() + orig_method.get_descriptor()]
    return class_all_words
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
    # path = "F:\\2018年第一学年科研\\APK科研\\数据集\\amd_data\\AndroRAT\\variety1\\a537253264aae9dd0fc41105a5f02d51.apk"
    #
    # Bulid_Corpus(path)
    path = 'D:\\APK_科研\\数据集\\DroidKungFu\\variety1'
    all_amd_path = Read_amd_data(path)
    with open('D:\\APK_科研\\数据集\\new_amd_callback_data1.csv', 'w', newline='')as csvfile:
        writer=csv.writer(csvfile)
        for path in range(len(all_amd_path)):
            print(all_amd_path[path])
            # Build_Class_Word2Vec(path)
            try:  # 因为在读取amd_data的时候会出现错误
                Bulid_Corpus(all_amd_path[path],writer)
            except Exception:
                print('出错')
                path += 1

#用于处理非AMD数据集
def Deal_all_data():
    path='F:\\2018年第一学年科研\\APK科研\\数据集\\seprated_apks\\entertainment_succeed\\br.com.frs.foodrestrictions_2.apk'
    Deal_one_apk(path)
    # write_one_apk_source(path)
if __name__ == "__main__":

    Deal_all_amd_data()