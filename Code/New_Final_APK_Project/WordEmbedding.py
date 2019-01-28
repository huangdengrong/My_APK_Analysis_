# -*- coding: utf-8 -*-
import multiprocessing
from gensim.models import Word2Vec
import csv
def embedding_sentences(sentences, embedding_size = 64, window = 3, min_count = 0, file_to_load = None, file_to_save = None):
    '''
    embeding_size 词嵌入维数
    window : 上下文窗口
    min_count : 词频少于min_count会被删除
    '''
    #  模型保存与载入
    if file_to_load is not None:
        w2vModel = Word2Vec.load(file_to_load)  # 用于加载模型
    else:
        w2vModel = Word2Vec(sentences, size = embedding_size, window = window, min_count = min_count, workers = multiprocessing.cpu_count(),seed=200)
        if file_to_save is not None:
            w2vModel.save(file_to_save)     # 保存模型
    return w2vModel
# 此函数用于将一个句子表示为向量(对应于将一个method表示为向量)
def get_method_vector(sentence,w2vModel):
    sentence_vector=[]
    for word in sentence:
        sentence_vector.append(w2vModel[word])#用于将每个单词的词向量添加进来
    return sentence_vector
# 此函数用于将一个单词表示为向量（对应于method中的一个word）
def get_word_vector(word,w2vModel):
    return w2vModel[word]
# 此函数用于获取一个文本的vector(对应于class或者apk的词向量)
def get_apk_class_vector(document,w2vModel):
    all_vectors = []
    embeddingDim = w2vModel.vector_size
    # 嵌入维数
    embeddingUnknown = [0 for i in range(embeddingDim)]
    for sentence in document:
        this_vector = []
        for word in sentence:
            if word in w2vModel.wv.vocab:
                this_vector.append(w2vModel[word])
            else:
                this_vector.append(embeddingUnknown)
        all_vectors.append(this_vector)
    return all_vectors
#   此函数用于获取俩个sentence之间的相似度，借助python自带的计算相似度的函数
def get_two_sentence_simility(sentence1,sentence2,w2vModel):
    sim = w2vModel.n_similarity(sentence1, sentence2)
    return sim
#  用于建立语料库
def bulid_word2vec_model():#用于建立word2vec模型
    model = embedding_sentences(get_corpus_(), embedding_size=16,
                                min_count=0,
                                file_to_save='F:/2018年第一学年科研/APK科研/数据集/Word2vec_ao_yuliaoku/apk_trained_word2vec.model')
    return model
# 用于获取已经创建好的model
def get_already_word2vec_model(file_to_load):
    model = Word2Vec.load(file_to_load)
    return model
# 用于获取语料库
def get_corpus():
    all_data=[]
    data_readers=csv.reader(open('F:/2018年第一学年科研/APK科研/数据集/Word2vec_ao_yuliaoku/new_amd_callback_data1.csv'))
    for reader in data_readers:
        if len(reader)>1:
            # print(reader)
            all_data.append(reader)
    amd_data_readers=csv.reader(open('F:/2018年第一学年科研/APK科研/数据集/Word2vec_ao_yuliaoku/new_callback_data1.csv'))
    for amd_reader in amd_data_readers:
        if len(amd_reader)>1:
            # print(amd_reader)
            all_data.append(amd_reader)
    print('over')
    return all_data
def get_corpus_():
    all_data = []
    data_readers = csv.reader(open('F:/2018年第一学年科研/APK科研/数据集/Word2vec_ao_yuliaoku/new_amd_callback_data.csv'))
    for reader in data_readers:
        if len(reader) > 1:
            # print(reader)
            all_data.append(reader)
    amd_data_readers = csv.reader(open('F:/2018年第一学年科研/APK科研/数据集/Word2vec_ao_yuliaoku/new_amd_callback_data1.csv'))
    for amd_reader in amd_data_readers:
        if len(amd_reader) > 1:
            # print(amd_reader)
            all_data.append(amd_reader)
    amd_data_readers_=csv.reader(open('F:/2018年第一学年科研/APK科研/数据集/Word2vec_ao_yuliaoku/new_callback_data.csv'))
    for amd_reader_ in amd_data_readers_:
        if len(amd_reader_)>1:
            all_data.append(amd_reader_)
    print('over')
    return all_data
if __name__ == "__main__":
    bulid_word2vec_model()