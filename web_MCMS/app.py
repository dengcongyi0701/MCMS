#!/usr/bin/env python3
# -*-coding: utf-8 -*-
"""
Created on 2022/1/3 13:35

__author__ = "NKAMG"
__copyright__ = "Copyright (c) 2022 NKAMG"
__license__ = "GPL"
__contact__ = ""

Description:

"""

from flask import Flask, render_template, request, send_file, jsonify
import json
import sys
import imp
import re
import os
import string
from configparser import ConfigParser
from dga_detection import MultiModelDetection
from search import get_info_by_sha256
from search import get_info_by_md5
from search import get_info_all
from web_download import get_torrent_file
from web_download import get_tgz_file
from web_download import get_torrent_files
from web_download import get_tgz_files

cp = ConfigParser()
cp.read('config.ini')
HOST_IP = cp.get('ini', 'ip')
PORT = int(cp.get('ini', 'port'))
ROW_PER_PAGE = int(cp.get('ini', 'row_per_page'))
detector = MultiModelDetection()

imp.reload(sys)
app = Flask(__name__)


list_info = []

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, int):
            return int(obj)
        if isinstance(obj, str):
            return str(obj)

def get_page_info(list_info, offset=0, per_page=ROW_PER_PAGE):
    return list_info[offset: offset + per_page]


@app.route('/')
def show_index():
    # 样本数量
    sample_size = int(100000000/10000)
    # 样本类型
    sample_type = {"maltype": ["AndroidOS", "JS", "RTF", "VBS", "E", "F", "G", "H"],
                   "num": [10000, 20000, 30000, 40000, 50000, 60000, 70000, 80000]}
    # 样本具体类型
    sample_type_details = {"detailed_type": ["HEUR:Trojan-Downloader", "Trojan-Dropper", "HEUR-Exploit", "HEUR-Trojan",
                                             "AndroidVirus", "UDS:DangerousObject", "Backdoor", "AAAA", "BBBB", "CCCC",
                                             "abcd", "efgh", "hijk", "lmno"],
                           "num": [4220000, 3450000, 2900000, 2240000, 1960000, 1860000, 2785, 2623, 1948, 1000, 500,
                                    200, 53, 39]}
    # 样本增加情况
    sample_addtions = {"date": ["8周前", "7周前", "6周前", "5周前", "4周前", "3周前", "2周前", "1周前", "现在"],
                       "total_num": [2100000, 2101000, 2131000, 2133000, 2134234, 2146547, 2150040, 2154563, 2160491, 2184391],
                       "new_sample_num": [1000, 30000, 2000, 1234, 12313, 3493, 4523, 5928, 23900],}
    # 样本大小
    sample_attribute = {"interval": ['小于1KB', "1KB~10KB", "10KB~100KB", "100KB~1MB", "1MB~10MB", "大于10MB"],
                        "num": [100000, 130000, 210000, 134539, 153123, 78927]}
    # 样本年度统计
    sample_year = {"year": ['2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'],
                   "num": [194831, 211204, 329193, 139102, 352819, 285239, 70983, 129481, 568520, 93820, 109931, 539283, 33884]
                   }
    # 样本家族
    sample_family = {"family": ["FNameA", "FimilyNameB", "fnC", "FmlND", "FmlNE", "F", "GNG", "fmlnmh"],
                     "num": [535639, 454109, 148391, 63928, 32849, 18000, 12999, 6382]}

    return render_template('malicious_sample_statistics.html',
                           sp_size=sample_size,
                           sp_type=sample_type,
                           tp_details=sample_type_details,
                           sp_addtions=sample_addtions,
                           sp_attribute=sample_attribute,
                           sp_year=sample_year,
                           sp_family=sample_family)

@app.route('/malurl_query', methods=["POST", "GET"])
def malurl_page():
    # 恶意域名数量
    url_total = {"total": 520618714,
                 "mal": 205016624,
                 "benign": 315602090}
    # 恶意域名统计数据
    url_num = {"date":['2021-02-20', '2021-02-21', '2021-02-22', '2021-02-23', '2021-02-24', '2021-02-25', '2021-02-26',
                       '2021-02-27', '2021-02-28', '2021-03-01', '2021-03-02', '2021-03-03', '2021-03-04', '2021-03-05',
                       '2021-03-06', '2021-03-07', '2021-03-08', '2021-03-09', '2021-03-10', '2021-03-11', '2021-03-12',
                       '2021-03-13', '2021-03-14', '2021-03-15', '2021-03-16', '2021-03-17', '2021-03-18', '2021-03-19',
                       '2021-03-20', '2021-03-21', '2021-03-22', '2021-03-23', '2021-03-24', '2021-03-25', '2021-03-26',
                       '2021-03-27',  '2021-03-28', '2021-03-29', '2021-03-30', '2021-03-31', '2021-04-01', '2021-04-02',
                       '2021-04-03', '2021-04-04', '2021-04-05', '2021-04-06', '2021-04-07', '2021-04-08', '2021-04-09',
                       '2021-04-10', '2021-04-11', '2021-04-12', '2021-04-13', '2021-04-14', '2021-04-15', '2021-04-16',
                       '2021-04-17', '2021-04-18', '2021-04-19', '2021-04-20', '2021-04-21', '2021-04-22', '2021-04-23',
                       '2021-04-24', '2021-04-25', '2021-04-26', '2021-04-27', '2021-04-28', '2021-04-29', '2021-04-30',
                       '2021-05-01', '2021-05-02', '2021-05-03', '2021-05-04', '2021-05-05', '2021-05-06', '2021-05-07',
                       '2021-05-08', '2021-05-09', '2021-05-10', '2021-05-11', '2021-05-12', '2021-05-13', '2021-05-14',
                       '2021-05-15', '2021-05-16', '2021-05-17', '2021-05-18', '2021-05-19', '2021-05-20', '2021-05-21',
                       '2021-05-22', '2021-05-23', '2021-05-24', '2021-05-25', '2021-05-26', '2021-05-27', '2021-05-28',
                       '2021-05-29', '2021-05-30', '2021-05-31', '2021-06-01', '2021-06-02', '2021-06-03', '2021-06-04',
                       '2021-06-05', '2021-06-06', '2021-06-07', '2021-06-08', '2021-06-09', '2021-06-10', '2021-06-11',
                       '2021-06-12', '2021-06-13', '2021-06-14', '2021-06-15', '2021-06-16', '2021-06-17', '2021-06-18',
                       '2021-06-19', '2021-06-20', '2021-06-21', '2021-06-22', '2021-06-23', '2021-06-24', '2021-06-25',
                       '2021-06-26', '2021-06-27', '2021-06-28', '2021-06-29', '2021-06-30', '2021-07-01', '2021-07-02',
                       '2021-07-03', '2021-07-04', '2021-07-05', '2021-07-06', '2021-07-07', '2021-07-08', '2021-07-09',
                       '2021-07-10', '2021-07-11', '2021-07-12', '2021-07-13', '2021-07-14', '2021-07-15', '2021-07-16',
                       '2021-07-17', '2021-07-18', '2021-07-19', '2021-07-20', '2021-07-21', '2021-07-22', '2021-07-23',
                       '2021-07-24', '2021-07-25', '2021-07-26', '2021-07-27', '2021-07-28', '2021-07-29', '2021-07-30',
                       '2021-07-31', '2021-08-01', '2021-08-02', '2021-08-03', '2021-08-04', '2021-08-05', '2021-08-06',
                       '2021-08-07', '2021-08-08', '2021-08-09', '2021-08-10', '2021-08-11', '2021-08-12', '2021-08-13',
                       '2021-08-14', '2021-08-15', '2021-08-16', '2021-08-17', '2021-08-18', '2021-08-19', '2021-08-20',
                       '2021-08-21', '2021-08-22', '2021-08-23', '2021-08-24', '2021-08-25', '2021-08-26', '2021-08-27',
                       '2021-08-28', '2021-08-29', '2021-08-30', '2021-08-31', '2021-09-01', '2021-09-02', '2021-09-03',
                       '2021-09-04', '2021-09-05', '2021-09-06', '2021-09-07', '2021-09-08', '2021-09-09', '2021-09-10',
                       '2021-09-11', '2021-09-12', '2021-09-13', '2021-09-14', '2021-09-15', '2021-09-16', '2021-09-17',
                       '2021-09-18', '2021-09-19', '2021-09-20', '2021-09-21', '2021-09-22', '2021-09-23', '2021-09-24',
                       '2021-09-25', '2021-09-26', '2021-09-27', '2021-09-28', '2021-09-29', '2021-09-30', '2021-10-01',
                       '2021-10-02', '2021-10-03', '2021-10-04', '2021-10-05', '2021-10-06', '2021-10-07', '2021-10-08',
                       '2021-10-09', '2021-10-10', '2021-10-11', '2021-10-12', '2021-10-13', '2021-10-14', '2021-10-15',
                       '2021-10-16', '2021-10-17', '2021-10-18', '2021-10-19', '2021-10-20', '2021-10-21', '2021-10-22',
                       '2021-10-23', '2021-10-24', '2021-10-25', '2021-10-26', '2021-10-27', '2021-10-28', '2021-10-29',
                       '2021-10-30', '2021-10-31', '2021-11-01', '2021-11-02', '2021-11-03', '2021-11-04', '2021-11-05',
                       '2021-11-06', '2021-11-07', '2021-11-08', '2021-11-09', '2021-11-10', '2021-11-11', '2021-11-12',
                       '2021-11-13', '2021-11-14', '2021-11-15', '2021-11-16', '2021-11-17', '2021-11-18', '2021-11-19',
                       '2021-11-20', '2021-11-21', '2021-11-22', '2021-11-23', '2021-11-24', '2021-11-25', '2021-11-26',
                       '2021-11-27', '2021-11-28', '2021-11-29', '2021-11-30', '2021-12-01', '2021-12-02', '2021-12-03',
                       '2021-12-04', '2021-12-05', '2021-12-06', '2021-12-07', '2021-12-08', '2021-12-09', '2021-12-10',
                       '2021-12-11', '2021-12-12', '2021-12-13'],
               "num": [871720, 888167, 887926, 889030, 851257, 867373, 867420, 851093, 870072, 887601, 885561, 871155,
                       871068, 887499, 867567, 850179, 851280, 876642, 899018, 861569, 882387, 898633, 897800, 0, 860288,
                       857779, 878570, 874016, 902988, 902006, 903127, 901418, 901418, 912190, 863501, 879867, 878895,
                       863605, 883799, 900162, 908965, 883661, 894700, 909774, 891038, 874549, 874718, 888710, 910820,
                       893631, 893498, 910853, 910997, 894556, 871726, 890684, 890886, 863747, 864684, 913100, 914638,
                       893380, 912272, 911203, 911476, 874878, 891076, 891169, 874548, 894669, 911029, 908083, 894763,
                       884778, 911230, 891130, 863835, 874847, 888140, 911339, 883942, 894896, 901421, 910927, 871876,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 879677, 873054, 894233, 910509, 908624, 893919, 894042,
                       910409, 889514, 874144, 874276, 888657, 910621, 894065, 894259, 909530, 910786, 894267, 872407,
                       890508, 879657, 912737, 912278, 911139, 927870, 906932, 906862, 868421, 884788, 883831, 868463,
                       888565, 904919, 902811, 888332, 888548, 903905, 885046, 868538, 868556, 882661, 904770, 888288,
                       887354, 880625, 880769, 880613, 890217, 890394, 891515, 890350, 900719, 891469, 892615, 891429,
                       901852, 892692, 890505, 900712, 891295, 892481, 880251, 901699, 891345, 892453, 891322, 900608,
                       891379, 893585, 891452, 900789, 891407, 892569, 890917, 900700, 892370, 880286, 892568, 968341,
                       900701, 892464, 881698, 865655, 891410, 892599, 901814, 0, 0, 0, 0, 978797, 1029306, 1011559,
                       1020803, 1049109, 1048276, 1032994, 1033054, 1049732, 1028309, 1012632, 1013140, 1028513, 1050252,
                       1033937, 1015444, 425774, 425624, 434960, 434875, 435859, 508843, 407086, 396130, 396130, 396130,
                       0, 0, 392204, 426502, 417151, 517984, 425797, 447891, 426584, 451121, 459144, 425993, 432809,
                       449262, 429047, 412523, 412391, 426976, 458059, 431472, 432258, 441931, 448103, 432539, 410979,
                       427059, 429397, 413011, 452751, 459233, 451548, 451382, 448278, 452170, 410337, 428411, 427552,
                       414277, 451330, 448123, 434420, 434640, 451531, 430849, 414323, 413484, 429218, 451188, 434372,
                       434496, 450622, 451022, 432868, 411094, 431008, 430737, 430996, 414339, 452616, 441960, 431587,
                       442521, 440512, 441791, 415872, 420069, 418788, 429679, 434109, 424339, 449702, 434513, 0, 0, 0,
                       0, 0, 396532, 449276, 423741, 433519, 439429, 428121],
        }
    return render_template("malware_url_query.html",
                           url_total=url_total,
                           url_num=url_num)

@app.route('/malurl_result', methods=["POST"])
def detect_url():
    # 1. get url string
    url_str = request.form["url"].strip()
    # 2. validate string
    if url_str == '':
        return render_template("malware_url_result.html",
                           status=400, url=url_str,
                           message="域名不可为空!!")
    validate = re.match(r"^[A-Za-z0-9._\-]*$", url_str)
    if validate == None:
        return render_template("malware_url_result.html",
                               status=401, url=url_str,
                               message="域名格式不正确，域名中只能包含下划线、短横线、点、字母、数字，请输入正确域名！")
    results = detector.multi_predict_single_dname(url_str)
    return render_template("malware_url_result.html", status=200, url=url_str, base_result=results[0],
                           result=results[1])

# 样本查询页面
@app.route('/malsample_search')
def malsample_search_page():
    return render_template('malicious_sample_search.html')

# 综合查询
@app.route('/search_all', methods=['POST'])
def search_all():
    global list_sha256
    # 1. Get search parameters
    platform = request.form['platform']
    category = request.form['category']
    family = request.form['family']
    scan_result = request.form['scan_result']
    year = request.form['year']
    feature = request.form['feature']

    # 2. Get matched sha256 list
    list_info = get_info_all(platform, category, family, scan_result, year, feature)

    # 3. Check match list
    if not len(list_info):
        return render_template('error.html', \
                title = "没有找到符合条件的恶意代码样本",\
                scan_sha256 = "")
    list_sha256 = []
    for i in list_info:
        list_sha256.append(i["sha256"])

    print(len(list_sha256))
    print(list_sha256[0])

    print(len(list_sha256))
    # 4. Use list.html template to show search results
    return render_template('list.html',
                           list_info = list_info)

# SHA256搜索
@app.route('/search_sha256', methods=['POST'])
def search_sha256():
    # 1. Get sha256
    sha256 = request.form['sha256']
    # 2. Validate sha256
    # 2.1 check length of sha256 string
    if len(sha256) != 64:
        return render_template('error.html',
                               title="SHA256字符串不合法，长度不是64字符！",
                               scan_sha256=sha256)
    # 2.2 Check hexdecimal characters
    if not all(x in string.hexdigits for x in str(sha256)):
        return render_template('error.html',
                               title="SHA256字符串不合法，包含不合法的十六进制字符！",
                               scan_sha256=sha256)
    # 3. Get json info
    dict_json = get_info_by_sha256(sha256)
    if not dict_json:
        return render_template('error.html',
                               title="恶意代码样本库中没有找到样本信息",
                               scan_sha256=sha256)

    title = "恶意代码样本信息"

    # 4. Get scan results
    if len(dict_json.keys()) == 2:
        scans = dict_json["results"]["scans"]
        md5 = dict_json["results"]["md5"]
    else:
        scans = dict_json['scans']
        md5 = dict_json["md5"]

    d = {}
    for key, value in scans.items():
        if value['detected']:
            d[key] = {'result': value['result'], 'version': value['version']}
        else:
            d[key] = {'result': "CLEAN", 'version': value['version']}

    kav_result = d["Kaspersky"]["result"]
    if ":" in kav_result:
        kav_result = kav_result.split(":")[1]
    print(kav_result)
    # AdWare.MSIL.Ocna.aps
    list_kav = kav_result.split(".")
    category = list_kav[0]
    platform = list_kav[1]
    family = list_kav[2]

    return render_template('detail.html',
                           title=title,
                           scans=d,
                           scan_sha256=sha256,
                           scan_md5=md5,
                           platform=platform,
                           category=category,
                           family=family)


# MD5搜索
@app.route('/search_md5', methods=['POST'])
def search_md5():
    # 1. Get MD5
    md5 = request.form['md5']

    # 2. Validate MD5
    # 2.1 check length of md5 string
    if len(md5) != 32:
        return render_template('error.html',
                               title="MD5字符串不合法，长度不是32字符！",
                               scan_md5=md5,
                               scan_sha256="")
    # 2.2 Check hexdecimal characters
    if not all(x in string.hexdigits for x in str(md5)):
        return render_template('error.html',
                               title="MD5字符串不合法，包含不合法的十六进制字符！",
                               scan_md5=md5,
                               scan_sha256="")
    # 4. Get json info
    dict_json = get_info_by_md5(md5)
    if not dict_json:
        return render_template('error.html',
                               title="恶意代码样本库中没有找到样本信息",
                               scan_md5=md5,
                               scan_sha256="")
    title = "恶意代码样本信息"

    # 5. Get scan results
    if len(dict_json.keys()) == 2:
        scans = dict_json["results"]["scans"]
        sha256 = dict_json["results"]["sha256"]
    else:
        scans = dict_json['scans']
        sha256 = dict_json["sha256"]
    d = {}
    for key, value in scans.items():
        if value['detected']:
            d[key] = {'result': value['result'], 'version': value['version']}
        else:
            d[key] = {'result': "CLEAN", 'version': value['version']}


    kav_result = d["Kaspersky"]["result"]
    if ":" in kav_result:
        kav_result = kav_result.split(":")[1]
    print(kav_result)
    # AdWare.MSIL.Ocna.aps
    list_kav = kav_result.split(".")
    category = list_kav[0]
    platform = list_kav[1]
    family = list_kav[2]

    return render_template('detail.html',
                           title=title,
                           scans=d,
                           scan_md5=md5,
                           scan_sha256=sha256,
                           platform=platform,
                           category=category,
                           family=family)
@app.route('/detail')
def detail():
    scans = dict_json['scans']
    sha256 = dict_json['sha256']
    d = {}
    for key, value in scans.items():
        if value['detected']:
            d[key] = {'result':value['result'], 'version':value['version']}
        else:
            d[key] = {'result':"CLEAN", 'version':value['version']}

    for key, value in d.items():
        print("{}: {}".format(key, value))

    return render_template('detail.html', \
            title = title,\
            scans = d,\
            scan_sha256 = sha256)

# 下载样本
@app.route('/sha256/<sha256>')
def download_sha256(sha256):
    path = "../DATA/sha256/" + sha256[0] + '/' +  sha256[1] + '/' + sha256[2] + '/' + sha256[3] + '/' + sha256
    path = os.path.abspath(path)
    print(path)
    return send_file(path, as_attachment=True)

@app.route('/tgz/<sha256>')
def download_tgz(sha256):
    f_tgz = get_tgz_file(sha256)
    print("[Web] Get tgz file {}".format(f_tgz))
    return send_file(f_tgz, as_attachment=True)

@app.route('/torrent/<sha256>')
def download_torrent(sha256):
    f_torrent = get_torrent_file(sha256)
    print("[Web] Get torrent file {}".format(f_torrent))
    return send_file(f_torrent, as_attachment=True)

@app.route('/tgz_list/')
def download_tgz_list():
    global list_sha256
    print(list_sha256[0])
    f_tgz = get_tgz_files(list_sha256)
    print(f_tgz)
    print("[Web] Get tgz file {}".format(f_tgz))
    return send_file(f_tgz, as_attachment=True)

@app.route('/torrent_list/')
def download_torrent_list():
    global list_sha256
    f_torrent = get_torrent_files(list_sha256)
    print("[Web] Get torrent file {}".format(f_torrent))
    return send_file(f_torrent, as_attachment=True)

def search_data():
    global labels
    global contents
    global slabels
    global scontents
    global title
    global stitle
    global atitle
    global alabels
    global acontents
    global ititle
    global ilabels
    global icontents
    global icontents_
    global etitle
    global elabels
    global econtents
    global dict_json
    # 1. Get sha256 value for search
    sha256 = request.get_data()
    sha256 = bytes.decode(sha256)
    print("[i] Get SHA256: {}".format(sha256))
    #print(sha256)

    # 2. Get json info
    dict_json = get_json_info(sha256)
    if dict_json:
        title = "恶意代码样本信息"
    else:
        title = "恶意代码样本库中没有找到样本信息"

    # 3. Check

    return jsonify({ title:title })
if __name__ == '__main__':
    app.run(host=HOST_IP, port=PORT, threaded=True)
