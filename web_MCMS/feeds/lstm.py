# -*- coding: utf-8 -*-
"""
Created on 2022/1/3 15:45

__author__ = "Congyi Deng"
__copyright__ = "Copyright (c) 2021 NKAMG"
__license__ = "GPL"
__contact__ = "dengcongyi0701@163.com"

Description:

"""
import pandas as pd
import numpy as np
import math
import string
import collections
from sklearn.metrics import precision_score, recall_score, accuracy_score, f1_score
from sklearn.model_selection import StratifiedShuffleSplit
from keras.models import model_from_json
from keras.preprocessing import sequence
from keras.models import Sequential
from keras.layers.core import Dense, Dropout, Activation
from keras.layers.embeddings import Embedding
from keras.layers.recurrent import LSTM


class LSTMClassifier:
    def __init__(self):
        self.model = None
        self.valid_chars = {'q': 17, '0': 27, 'x': 24, 'd': 4, 'l': 12, 'm': 13, 'v': 22, 'n': 14, 'c': 3, 'g': 7, '7': 34, 'u': 21, '5': 32, 'p': 16, 'h': 8, 'b': 2, '6': 33, '-': 38, 'z': 26, '3': 30, 'f': 6, 't': 20, 'j': 10, '1': 28, '4': 31, 's': 19, 'o': 15, 'w': 23, '9': 36, 'r': 18, 'i': 9, 'e': 5, 'y': 25, 'a': 1, '.': 37, '2': 29, '_': 39, '8': 35, 'k': 11}
        self.maxlen = 178
        self.max_features = 40
        self.max_epoch = 20  # 20
        self.batch_size = 128
        self.tld_list = []
        self.isload_ = False
        with open(r'./data/tld.txt', 'r', encoding='utf8') as f:
            for i in f.readlines():
                self.tld_list.append(i.strip()[1:])

        score_df = pd.read_csv(r"./data/lstm_score_rank.csv", names=['score'])
        self.score_l = score_df['score'].tolist()

    def build_binary_model(self):
        """Build LSTM model for two-class classification"""
        self.model = Sequential()
        self.model.add(Embedding(self.max_features, 128, input_length=self.maxlen))
        self.model.add(LSTM(128))
        self.model.add(Dropout(0.5))
        self.model.add(Dense(1))
        self.model.add(Activation('sigmoid'))
        self.model.compile(loss='binary_crossentropy',optimizer='rmsprop')

    def create_class_weight(self, labels_dict, mu):
        """Create weight based on the number of sld name in the dataset"""
        labels_dict = dict(labels_dict)
        keys = labels_dict.keys()
        total = labels_dict[1] + labels_dict[0]
        class_weight = dict()
        for key in keys:
            score = math.pow(total/float(labels_dict[key]), mu)
            class_weight[key] = score
        return class_weight

    def train(self, model_folder, train_feature_add):
        """
        ????????????
        :param model_folder: ?????????????????????
        :param test_feature_add: ????????????????????????
        :return:
        """
        model_add = "{}/LSTM_model.json".format(model_folder)  # ????????????
        model_weight = "{}/LSTM_model.h5".format(model_folder)  # ????????????
        # ?????????????????????????????? domain???label
        train_df = pd.read_csv(train_feature_add, header=[0])
        train_df = train_df.iloc[:, 0:2]
        train_df["domain_name"] = train_df["domain_name"].apply(self.data_pro)
        sld = train_df["domain_name"].to_list()
        label = train_df["label"].to_list()
        X = [[self.valid_chars[y] for y in x] for x in sld]
        X = sequence.pad_sequences(X, maxlen=self.maxlen)
        y = np.array(label)
        sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=4)
        for train, test in sss.split(X, y):
            X_train, X_test, y_train, y_test = X[train], X[test], y[train], y[test]
            print("---train:{}---test:{}----y_train:{}----y_test:{}".format(len(X_train), len(X_test), len(y_train),
                                                                            len(y_test)))
            # shuffle
            np.random.seed(4)  # 1024
            index = np.arange(len(X_train))
            np.random.shuffle(index)
            X_train = np.array(X_train)[index]
            y_train = np.array(y_train)[index]
            # build model
            self.build_binary_model()
            # train
            sss1 = StratifiedShuffleSplit(n_splits=1, test_size=0.05, random_state=0)
            for train, test in sss1.split(X_train, y_train):
                X_train, X_holdout, y_train, y_holdout = X_train[train], X_train[test], y_train[train], y_train[test]  # holdout?????????
            labels_dict = collections.Counter(y_train)
            class_weight = self.create_class_weight(labels_dict, 0.3)
            print('----class weight:{}'.format(class_weight))
            # 20
            best_acc = 0.0
            best_model = None
            for ep in range(self.max_epoch):
                self.model.fit(X_train, y_train, batch_size=self.batch_size, epochs=1, class_weight=class_weight)
                t_probs = self.model.predict_proba(X_holdout)
                t_result = [0 if x <= 0.5 else 1 for x in t_probs]
                t_acc = accuracy_score(y_holdout, t_result)
                print("epoch:{}--------val acc:{}---------best_acc:{}".format(ep, t_acc, best_acc))
                if t_acc > best_acc:
                    best_model = self.model
                    best_acc = t_acc
            model_json = best_model.to_json()
            # ????????????????????????HDF5???
            # ????????????????????????JSON????????????YAML?????????
            with open(model_add, "w") as json_file:
                json_file.write(model_json)
                self.model.save_weights(model_weight)
            print("Saved two-class model to disk")

        # ?????????????????????
        # self.load(model_folder)
        y_pred = self.model.predict_proba(X, batch_size=self.batch_size, verbose=1)
        y_pred = y_pred.flatten()
        df = pd.DataFrame(y_pred)
        df = df.sort_values(by=0, ascending=False)
        df.to_csv("./data/model/LSTM_train_scores.csv", index=False, header=None)

    def load(self, model_folder):
        """
        ?????????????????????????????????
        :param model_folder: ?????????????????????
        :return:
        """
        model_add = "{}/LSTM_model.json".format(model_folder)  # ????????????
        model_weight_add = "{}/LSTM_model.h5".format(model_folder)  # ????????????
        with open(model_add, 'r') as json_file:
            model = json_file.read()
        self.model = model_from_json(model)
        self.model.load_weights(model_weight_add)
        score_df = pd.read_csv("{}/LSTM_train_scores.csv".format(model_folder), names=['score'])
        self.score_l = score_df['score'].tolist()
        self.isload_ = True
        # ????????????????????????????????????????????????????????????????????????????????????????????????????????????

    def data_pro(self, url):
        """
        ??????????????????
        :param url:
        :return:
        """
        url = url.strip().strip('.').strip('/')
        url = url.replace("http://", '')
        url = url.split('/')[0]
        url = url.split('?')[0]
        url = url.split('=')[0]
        dn_list = url.split('.')
        for i in reversed(dn_list):
            if i in self.tld_list:
                dn_list.remove(i)
            elif i == 'www':
                dn_list.remove(i)
            else:
                continue
        short_url = ''.join(dn_list)
        short_url = short_url.replace('[', '').replace(']', '')
        short_url = short_url.lower()
        return short_url

    def cal_p(self, s):
        """
        ??????p_value, ????????????
        :param s: float
        :return:
        """
        flag = 0  # score???da????????????
        for i in range(len(self.score_l)):
            if self.score_l[i] <= 0.5000000000000000:
                flag = i - 1
                break
        # print("flag:{}".format(flag))
        if s >= self.score_l[0]:
            return 1.0
        if s <= self.score_l[-1]:
            return 1.0
        if s == self.score_l[flag]:
            # return 1 / ((flag + 1) * 1.0)
            return 0.0

        high_index = len(self.score_l)
        low_index = 0
        while low_index < high_index:
            mid = int((low_index + high_index) / 2)
            if s > self.score_l[mid]:
                high_index = mid - 1
            elif s == self.score_l[mid]:
                if s > 0.5:
                    return (flag - mid + 1) / ((flag + 1) * 1.0)
                else:
                    return (mid - flag) / ((len(self.score_l) - flag - 1) * 1.0)
            else:
                low_index = mid + 1
        if s > 0.5:

            return round((flag - low_index) / ((flag + 1) * 1.0), 4)
        else:
            return round((low_index - flag) / ((len(self.score_l) - flag - 1) * 1.0), 4)

    def predict(self, model_folder, test_feature_add):
        """
        ????????????
        :param model_folder: ?????????????????????
        :param test_feature_add: ????????????????????????
        :return:
        """
        if not self.isload_:
            self.load(model_folder)
            self.isload_ = True
        # ????????????????????? domain???label
        df = pd.read_csv(test_feature_add, header=[0])
        df = df.iloc[:, 0:2]
        df["domain_name"] = df["domain_name"].apply(self.data_pro)
        sld = df["domain_name"].to_list()
        label = df["label"].to_list()
        X = [[self.valid_chars[y] for y in x] for x in sld]
        X = sequence.pad_sequences(X, maxlen=self.maxlen)
        y = np.array(label)
        # ??????
        y_pred = self.model.predict_proba(X, batch_size=self.batch_size, verbose=1)
        # ???????????????
        y_result = [0 if x <= 0.5 else 1 for x in y_pred]
        # ??????????????????????????????
        score = f1_score(y, y_result)
        precision = precision_score(y, y_result)
        recall = recall_score(y, y_result)
        acc = accuracy_score(y, y_result)
        print('LSTM accuracy:', acc)
        print('LSTM precision:', precision)
        print('LSTM recall:', recall)
        print('LSTM F1:', score)

    def predict_single_dname(self, model_folder, dname):
        """
        ???????????????????????????????????????????????????????????????
        :param model_folder: ?????????????????????
        :param dname: ??????
        :return:
        """
        if not self.isload_:
            self.load(model_folder)
            self.isload_ = True
        dname = dname.strip(string.punctuation)
        short_url = self.data_pro(dname)

        sld_int = [[self.valid_chars[y] for y in x] for x in [short_url]]
        sld_int = sequence.pad_sequences(sld_int, maxlen=self.maxlen)
        sld_np = np.array(sld_int)
        # ????????????
        self.model.compile(loss='binary_crossentropy', optimizer='rmsprop')
        if short_url == '':
            score = 0.0
            p_value = 1.0
            label = 0
            print("\nLSTM dname:", dname)
            print('label:{}, pro:{}, p_value:{}'.format(label, score, p_value))
            return label, score, p_value
        else:
            scores = self.model.predict(sld_np)
            score = scores[0][0]
            p_value = self.cal_p(score)

            if score > 0.5:
                label = 1
            else:
                label = 0
            print("\nLSTM dname:", dname)
            print('label:{}, pro:{}, p_value:{}'.format(label, score, p_value))
            return label, score, p_value
