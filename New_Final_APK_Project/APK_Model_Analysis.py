from APK_Method_Analysis import *
from matplotlib import pyplot
from mpl_toolkits.mplot3d import Axes3D
import random
from APK_Word2Vec_Simple_Weight_Vector import *
from sklearn.manifold import TSNE
'该脚本的功能是用于进行建立语料库，将所有的word保存到本地，然后进行后期词向量的转换'
def Analysis_APK_Model(apkfile):
    model_path = 'F:/2018年第一学年科研/APK科研/数据集/Word2vec_ao_yuliaoku/apk_trained_word2vec.model'
    model = get_already_word2vec_model(model_path)  # 用于获取已经训练好的word2vec模型

    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    a1, d1, dx = AnalyzeAPK(apkfile)
    CFG = nx.DiGraph()
    class_code_dic, is_amd_class_code_dic = Build_APK_Corpus(apkfile)

    method_message=[]
    all_methods=[]
    all_class=[]
    for k in d.get_classes():#对于每一个class
        all_class.append(k.get_name())
        all_orig_methods = []  # 用于统计所有的原始的方法
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
                    all_methods.append([orig_method.get_name() + orig_method.get_descriptor(),k.get_name()])
                    method_words=class_code_dic[k.get_name()][orig_method.get_name() + orig_method.get_descriptor()]

                    method_vector=get_method_vector(method_words,model,16)
                    # print(method_vector)
                    method_message.append(method_vector)
    print(all_methods)
    print(method_message)
    return all_methods,method_message,is_amd_class_code_dic,all_class
def show_APK(X,Z_,color):
    tsne = TSNE(n_components=2)
    X_tsne = tsne.fit_transform(X)
    print("Org data dimension is {}. Embedded data dimension is {}".format(X.shape[-1], X_tsne.shape[-1]))
    # print(tsne.embedding_)
    x_min, x_max = X_tsne.min(0), X_tsne.max(0)
    X_norm = (X_tsne - x_min) / (x_max - x_min)  # 归一化
    print(X_norm)
    X_Data = []
    Y_Data = []
    for k in X_norm:
        X_Data.append(k[0])
        Y_Data.append(k[1])
    print(len(X_Data))
    print(len(Y_Data))
    print(len(Z_))
    fig = pyplot.figure()
    ax = Axes3D(fig)
    ax.scatter(X_Data, Y_Data, Z_, c=color, marker='o')
    ax.set_xlabel('X Label')
    ax.set_ylabel('Y Label')
    ax.set_zlabel('Z Label')
    pyplot.show()
def Show_APKs(X,Y,Z,color_x,color_y):
    show_APK(X,Z,color_x)
    show_APK(Y,Z,color_y)
    pyplot.show()
def find_index(key,all_class):
    index=0
    for i,j in enumerate(all_class):
        # print('j:::'+j)
        if j ==key:
            index=i
            break
    return index
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
    path = "F:\\2018年第一学年科研\\APK科研\\数据集\\amd_data\\AndroRAT\\variety1\\0d02b9d5539893efc674fbacae14944a.apk"
    tsne = TSNE(n_components=2)
    all_methods, method_message, is_amd_class_code_dic,all_class = Analysis_APK_Model(path)
    #用于对所有的方法向量进行降维
    X_tsne = tsne.fit_transform(method_message)
    # print(X_tsne)
    print('长度：：'+str(len(X_tsne)))
    i=0
    Z=[]
    for key in all_methods:
        print(key)
        # print(all_class.)
        print(find_index(key[1],all_class))
        Z.append(find_index(key[1],all_class))
        # print(X_tsne[i])
        print(is_amd_class_code_dic[key[1]][key[0]])
        i+=1
        print('---------------------')
    print(i)
    show_APK(X_tsne,Z,'r')
def test():
    plt.title("I'm a scatter diagram.")
    plt.xlim(xmax=7, xmin=0)
    plt.ylim(ymax=7, ymin=0)
    plt.annotate("(3,6)", xy=(3, 6), xytext=(4, 5), arrowprops=dict(facecolor='black', shrink=0.1))
    plt.xlabel("x")
    plt.ylabel("y")
    plt.plot([1, 2, 3], [4, 5, 6], 'ro')
    plt.show()
def test_san():
    fig = pyplot.figure()
    ax = Axes3D(fig)
    sequence_containing_x_vals = list(range(0, 5))
    sequence_containing_y_vals = list(range(0, 5))
    sequence_containing_z_vals = list(range(0, 5))
    random.shuffle(sequence_containing_x_vals)
    random.shuffle(sequence_containing_y_vals)
    random.shuffle(sequence_containing_z_vals)
    name = ['a', 'b', 'c', 'd', 'e']
    for i in range(len(sequence_containing_x_vals)):
        ax.text(sequence_containing_x_vals[i], sequence_containing_y_vals[i], sequence_containing_z_vals[i], name[i])
    ax.scatter(sequence_containing_x_vals, sequence_containing_y_vals, sequence_containing_z_vals,c='r', marker='o')
    sequence_containing_x_vals = list(range(0, 5))
    sequence_containing_y_vals = list(range(0, 5))
    sequence_containing_z_vals = list(range(10, 15))

    random.shuffle(sequence_containing_x_vals)
    random.shuffle(sequence_containing_y_vals)
    random.shuffle(sequence_containing_z_vals)
    name = ['aaa', 'bbb', 'ccc', 'ddd', 'eee']
    for i in range(len(sequence_containing_x_vals)):
        ax.text(sequence_containing_x_vals[i], sequence_containing_y_vals[i], sequence_containing_z_vals[i], name[i])
    ax.scatter(sequence_containing_x_vals, sequence_containing_y_vals, sequence_containing_z_vals, c='g', marker='o')
    ax.set_xlabel('X Label')
    ax.set_ylabel('Y Label')
    ax.set_zlabel('Z Label')
    pyplot.show()
if __name__ == "__main__":
    # test_san()
    Deal_all_amd_data()