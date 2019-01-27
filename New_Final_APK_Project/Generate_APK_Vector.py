from APK_Word2Vec_Simple_Weight_Vector import *
from sklearn.manifold import TSNE
def main_():
    #将已经训练好的word2vec模型加载进来
    model_path = 'F:/2018年第一学年科研/APK科研/数据集/Word2vec_ao_yuliaoku/apk_trained_word2vec.model'
    model = get_already_word2vec_model(model_path)  # 用于获取已经训练好的word2vec模型
    # print(model)
    with open('F:\\2018年第一学年科研\\APK科研\\数据集\\Word2vec_ao_yuliaoku\\my_apk_vector.csv', 'w', newline='')as csvfile:
        writer = csv.writer(csvfile)
        path = 'F:\\2018年第一学年科研\\APK科研\\数据集\\github_APK'
        writer.writerow([path])
        all_amd_path = Read_amd_data(path)#此函数用来进行遍历所有的amd数据集
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
if __name__ == "__main__":
    main_()