from APK_Method_Analysis import *
from WordEmbedding import *
import math
import operator
#用于获取一个方法里面的所有的关键词
def Get_Method_Words(method_,class_,class_code_dic):
    method_words=[]
    method_words+=class_code_dic[class_.get_name()][method_.get_name() + method_.get_descriptor()]
    return method_words
#此函数用于获取一个class里面的所有的Word
def Get_Class_Words(class_,CFG,dx,class_code_dic):
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
                class_all_words.append(class_code_dic[class_.get_name()][orig_method.get_name() + orig_method.get_descriptor()])
    return class_all_words
#此函数用于获取一个apk里面的所有的关键词
def Get_APK_Words(apkfile):
    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    a1, d1, dx = AnalyzeAPK(apkfile)
    CFG = nx.DiGraph()
    apk_all_words=[]
    class_code_dic, is_amd_class_code_dic = Build_APK_Corpus(apkfile)
    for k in d.get_classes():  # 用于遍历每一个class
        class_all_words = Get_Class_Words(k, CFG, dx, class_code_dic)
        if len(class_all_words) != 0:
            apk_all_words.append(class_all_words)
    return apk_all_words
#用于获取每个单词的vector
def get_word_vector(word,w2vModel):

    embeddingDim = w2vModel.vector_size
    # 嵌入维数
    embeddingUnknown = [0 for i in range(embeddingDim)]
    if word in w2vModel.wv.vocab:
        return w2vModel[word]
    else:
        return embeddingUnknown

#此函数用于求出一个method的vector表示,没有采用tf-idf的格式
def get_method_vector(method_sentence,model,embedding_size):
    num = len(method_sentence)
    if num == 0:
        num = 1
    method_vector = [0 for i in range(embedding_size)]  # 用于生成embedding_size大小的向量，用于后面获取整个method的向量表示
    # 用于获取整个method的权重
    for word in method_sentence:
        word_vector = get_word_vector(word, model)
        # print(word_vector)
        method_vector = [word_vector[i] + method_vector[i] for i in range(len(word_vector))]
    method_vector = [i / num for i in method_vector]
    return method_vector
def get_class_vector(class_method,model,embedding_size):
    # my_corpus = WordEmbedding.get_corpus()  # 用于获取语料库
    class_vector = [0 for i in range(embedding_size)]
    num = len(class_method)
    if num == 0:
        num = 1
    for method_sentence in class_method:
        method_vector = get_method_vector(method_sentence, model, embedding_size)
        class_vector = [class_vector[i] + method_vector[i] for i in range(len(method_vector))]
    class_vector = [i / num for i in class_vector]
    return class_vector
def get_apk_vector(apk_classes,model,embedding_size):
    num = len(apk_classes)
    if num == 0:
        num = 1
    apk_vector = [0 for i in range(embedding_size)]
    for apk_class in apk_classes:
        class_vector = get_class_vector(apk_class, model, embedding_size)
        apk_vector = [apk_vector[i] + class_vector[i] for i in range(len(class_vector))]
    apk_vector = [i / num for i in apk_vector]
    return apk_vector
def Analysis_All_Apk(apkfile,writer):
    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    a1, d1, dx = AnalyzeAPK(apkfile)
    CFG = nx.DiGraph()
    apk_all_words = []
    class_code_dic, is_amd_class_code_dic = Build_APK_Corpus(apkfile)
    for k in d.get_classes():
        # print(k.get_superclassname())
        writer.writerow([k.get_superclassname()+'::'+k.get_name()])
        for m in dx.find_methods(classname=k.get_name()):  # 用于遍历一个class里面的所有的方法
            orig_method = m.get_method()
            if not isinstance(orig_method, ExternalMethod):
                if (orig_method.get_name() in all_callback) or (
                        orig_method.get_name() in APK_Method_Key_Words.key_registers):
                    # writer.writerow(orig_method.get_source())

                    # print(orig_method.get_name() + '::' + orig_method.get_descriptor())
                    writer.writerow([orig_method.get_name() + '::' + orig_method.get_descriptor()+'::'])
                    writer.writerow([orig_method.get_name()+orig_method.get_descriptor()]+class_code_dic[k.get_name()][orig_method.get_name() + orig_method.get_descriptor()])
                    # print(class_code_dic[k.get_name()][orig_method.get_name() + orig_method.get_descriptor()])
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
    model_path = 'F:/2018年第一学年科研/APK科研/数据集/Word2vec_ao_yuliaoku/apk_trained_word2vec.model'
    model = get_already_word2vec_model(model_path)  # 用于获取已经训练好的word2vec模型
    # print(model)
    with open('F:\2018年第一学年科研\APK科研\数据集\Word2vec_ao_yuliaoku\\apk_vector.csv', 'w', newline='')as csvfile:
        writer = csv.writer(csvfile)
        path = 'D:\\APK_科研\\数据集\\DroidKungFu\\amd\\'
        writer.writerow([path])
        all_amd_path = Read_amd_data(path)
        for path in range(len(all_amd_path)):
            print(all_amd_path[path])  # 因为在读取amd_data的时候会出现错误
            writer.writerow([all_amd_path[path]])
            try:
                apk_word = Get_APK_Words(all_amd_path[path])
                # print(apk_word)
                apk_vector = get_apk_vector(apk_word, model, 64)
                print(apk_vector)
                writer.writerow(apk_vector)
            except Exception:
                print('出错')
                path += 1
def Deal_All_APK():
    APK_path=Read_All_APK()
    # my_corpus = WordEmbedding.get_corpus()  # 用于获取语料库
    model_path='F:\\2018年第一学年科研\\APK科研\\word2vec\\apk_trained_word2vec.model'
    model=get_already_word2vec_model(model_path)#用于获取已经训练好的word2vec模型
    with open('F:/2018年第一学年科研/APK科研/数据集/Word2vec_ao_yuliaoku/apk_vector.csv', 'w', newline='')as csvfile:
        writer=csv.writer(csvfile)
        for path in APK_path:
            print(path)
            # Build_Class_Word2Vec(path)
            apk_word = Get_APK_Words(path)
            apk_vector = get_apk_vector(apk_word, model, 64)
            print(apk_vector)
            writer.writerow([path])
            writer.writerow(apk_vector)
        # writer.writerow()
        path = 'F:\\2018年第一学年科研\\APK科研\\数据集\\amd_data'
        writer.writerow([path])
        all_amd_path = Read_amd_data(path)
        for path in range(len(all_amd_path)):
            print(all_amd_path[path])
            try:  # 因为在读取amd_data的时候会出现错误
                apk_word = Get_APK_Words(all_amd_path[path])
                apk_vector = get_apk_vector(apk_word, model, 64)
                print(apk_vector)
                writer.writerow([all_amd_path[path]])
                writer.writerow(apk_vector)
            except Exception:
                print('出错')
                path += 1
def Read_All_APK():#此函数用于处理非恶意软件
    APK_path=[]
    path='F:\\2018年第一学年科研\\APK科研\\数据集\\seprated_apks\\'
    for _, _dirs, _ in os.walk(path):
        #root代表当前目录路径，dirs代表当前路径下的所有子目录，files代表当前目录下的所有非目录子文件
        for dir in _dirs:
            for root,dirs,files in os.walk(path+'\\'+dir):
                for file in files:
                    if os.path.splitext(file)[1] == '.apk':
                        APK_path.append(path+'\\'+dir+'\\'+file)
    return APK_path
def Analysis():
    path = 'D:\\APK_科研\\数据集\\DroidKungFu\\amd\\'
    all_amd_path = Read_amd_data(path)

    with open('D:\\APK_科研\\word2vec\\apk_vector2.csv', 'w', newline='')as csvfile:
        writer = csv.writer(csvfile)

        for path in range(len(all_amd_path)):
            print(all_amd_path[path])  # 因为在读取amd_data的时候会出现错误
            try:
                writer.writerow([all_amd_path[path]])
                Analysis_All_Apk(all_amd_path[path],writer)
            except Exception:
                print('出错')
                path += 1
def Test_Analysis_All_APK(apkfile):
    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    a1, d1, dx = AnalyzeAPK(apkfile)
    CFG = nx.DiGraph()
    apk_all_words = []
    class_code_dic, is_amd_class_code_dic = Build_APK_Corpus(apkfile)
    for k in d.get_classes():
        # print(dp.get_source_class(k))
        print('super_class+class::'+k.get_superclassname() + '::' + k.get_name())
        for m in dx.find_methods(classname=k.get_name()):  # 用于遍历一个class里面的所有的方法
            orig_method = m.get_method()
            if not isinstance(orig_method, ExternalMethod):
                if (orig_method.get_name() in all_callback) or (
                        orig_method.get_name() in APK_Method_Key_Words.key_registers):
                    print('method::'+orig_method.get_name() + '::' + orig_method.get_descriptor() + '::')
                    print([orig_method.get_name() + orig_method.get_descriptor()] + class_code_dic[k.get_name()][
                            orig_method.get_name() + orig_method.get_descriptor()])

                    # print(orig_method.get_source())

def Simple_simlarity_Analysis():
    model_path = 'F:/2018年第一学年科研/APK科研/数据集/Word2vec_ao_yuliaoku/apk_trained_word2vec.model'
    model = get_already_word2vec_model(model_path)  # 用于获取已经训练好的word2vec模型
    all_data=[]
    filename='F:\\2018年第一学年科研\\APK科研\\数据集\\Word2vec_ao_yuliaoku\\simility_analysis\\sim_vector.txt'
    with open(filename, 'r') as file_to_read:
        lines = file_to_read.readline()  # 整行读取数据
        all_data.append(lines)
        while len(lines)>0:
            lines = file_to_read.readline()  # 整行读取数据
            all_data.append(lines)
    new_all_data=[]
    for line in all_data:
        # line=line.split(',')
        line=re.split(',|\t\n|\n',line)
        line1=[]
        for i in line:
            if i != '':
                line1.append(i)
        new_all_data.append(line1)
    m1=new_all_data[18]
    m2=new_all_data[19]
    m3=new_all_data[20]
    m4=new_all_data[21]
    print(m1)
    print(m2)
    print(m3)
    print(m4)
    v1 = get_method_vector(m1, model, 16)
    v2 = get_method_vector(m2, model, 16)
    v3 = get_method_vector(m3, model, 16)
    v4 = get_method_vector(m4, model, 16)
    print(v1)
    print(v2)
    print(v3)
    print(v4)
    Cosin_Simility(v1, v2)
    Cosin_Simility(v3, v4)
    # cos_sim(v1,v2)
def Simple_simlarity_Analysis_():
    model_path = 'F:/2018年第一学年科研/APK科研/数据集/Word2vec_ao_yuliaoku/apk_trained_word2vec.model'
    model = get_already_word2vec_model(model_path)
    w1=['onDetachedFromWindow', 'Lbracket', 'Rbracket', 'void', 'b', 'Lbracket', 'Rbracket', 'void', 'b', 'Lbracket', 'Rbracket', 'void']
    w2=['onDetachedFromWindow', 'Lbracket', 'Rbracket', 'void', 'saveAvg2DB', 'Lbracket', 'Rbracket', 'void', 'b', 'Lbracket', 'Rbracket', 'void', 'saveAvg2DB', 'Lbracket', 'Rbracket', 'void', 'c', 'Lbracket', 'Rbracket', 'long', 'b', 'Lbracket', 'Rbracket', 'void']

    v1 = get_method_vector(w1, model, 16)
    v2 = get_method_vector(w2, model, 16)
    Cosin_Simility(v1, v2)
def Cosin_Simility(vector1,vector2):
    vector=[0 for i in range(len(vector1))]
    for i in range(len(vector1)):
        vector[i]=float(vector1[i])-float(vector2[i])
    sum=0.0
    for i in range(len(vector)):
        sum+=pow(vector[i],2)
    sum=math.sqrt(sum)
    # print(sum)
    return sum
def Analogy_Analisis():
    model_path = 'F:/2018年第一学年科研/APK科研/数据集/Word2vec_ao_yuliaoku/apk_trained_word2vec.model'
    model = get_already_word2vec_model(model_path)  # 用于获取已经训练好的word2vec模型
    all_data = []
    filename = 'F:\\2018年第一学年科研\\APK科研\\数据集\\Word2vec_ao_yuliaoku\\simility_analysis\\sim_vector.txt'
    with open(filename, 'r') as file_to_read:
        lines = file_to_read.readline()  # 整行读取数据
        all_data.append(lines)
        while len(lines) > 0:
            lines = file_to_read.readline()  # 整行读取数据
            all_data.append(lines)
    new_all_data = []
    for line in all_data:
        line = re.split(',|\t\n|\n', line)
        line1 = []
        for i in line:
            if i != '':
                line1.append(i)
        new_all_data.append(line1)
    m1 = new_all_data[28]
    m2 = new_all_data[29]
    m3 = new_all_data[25]
    m4 = new_all_data[24]
    print(m1)
    print(m2)
    print(m3)
    print(m4)
    v1 = get_method_vector(m1, model, 16)
    v2 = get_method_vector(m2, model, 16)
    v3 = get_method_vector(m3, model, 16)
    print(Cosin_Simility(v1,v2))
    print(Cosin_Simility(v2,v3))

    dictory={}
    for key in new_all_data:
        # print(key)
        if key !=m1 and key !=m2 and key !=m3 and key !=[]:
            # print(key)
            v4 = get_method_vector(key, model, 16)
            Distance=Cal_Other_Vector(v1,v2,v3,v4)
            dictory[key[0]]=Distance
    dictory=sorted(dictory.items(), key=operator.itemgetter(1),reverse=False)
    print(dictory)

def Cal_Other_Vector(v1,v2,v3,v4):
    d1=Cosin_Simility(v1,v4)
    d2=Cosin_Simility(v2,v4)
    d3=Cosin_Simility(v3,v4)

    Distance=d2-d1+d3
    return Distance
if __name__ == "__main__":
    Analogy_Analisis()
    # Simple_simlarity_Analysis_()
    # print(model)
    # Deal_all_amd_data()
    # Analysis()
    # # test()

