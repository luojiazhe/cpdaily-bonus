#coding=utf-8

import requests
import json
import hashlib
import base64
import pyaes
import time
from pyDes import des, CBC, PAD_PKCS5

LOGINAPI = 'http://localhost:port/login-api/api/login?login_url=https%3A%2F%2Fneau.campusphere.net%2Fiap%2Flogin%3Fservice%3Dhttps%3A%2F%2Fneau.campusphere.net%2Fportal%2Flogin'
LOGINURL = 'https://neau.campusphere.net/wec-counselor-sign-apps/stu/sign/submitSign'
TASKURL = 'https://neau.campusphere.net/wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay'
DETAILTASKURL = 'https://neau.campusphere.net/wec-counselor-sign-apps/stu/sign/detailSignInstance'
DESKEY = 'b3L26XNL'
AESKEY = 'ytUQ7l2ZZu8mLvJZ'

users = [
    {
        'username': '',
        'password': '',
        'lon': '126.732518',
        'lat': '45.750003',
        'position': '黑龙江省哈尔滨市香坊区'
    }
]

header = {
    'Host': 'neau.campusphere.net',
    'Accept': 'application/json, text/plain, */*',
    'X-Requested-With': 'XMLHttpRequest',
    'Accept-Language': 'zh-CN,zh-Hans;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Content-Type': 'application/json;charset=utf-8',
    'Origin': 'https://neau.campusphere.net',
    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 (4472147968)cpdaily/9.0.12  wisedu/9.0.12',
    'Connection': 'keep-alive',
    'Cookie': ''
}

liteHeader = {
    'User-Agent': '%E4%BB%8A%E6%97%A5%E6%A0%A1%E5%9B%AD/1 CFNetwork/1312 Darwin/21.0.0',
    'Cpdaily-Extension': '',
    'Cookie': '',
}


class Utils:
    @staticmethod
    def getTime():
        t = time.strftime("[%m-%d %H:%M:%S] ", time.localtime())
        return t

    @staticmethod
    def getCookie(user):
        postUrl = LOGINAPI + '&username=' + \
            user['username'] + '&password=' + user['password']
        resBody = json.loads(requests.post(url=postUrl).text)
        if resBody['msg'] == 'login success!':
            return resBody['cookies']
        return ''

    @staticmethod
    def getDeviceId(user):
        md5 = hashlib.md5()
        md5.update(user['username'].encode('utf8'))
        deviceId = md5.hexdigest().upper()
        deviceId = deviceId[0:8] + '-' + deviceId[8:12] + '-' + \
            deviceId[12:16] + '-' + deviceId[16:20] + '-' + deviceId[20:32]
        return deviceId

    @staticmethod
    def initStuInfo(user):
        user['cookie'] = Utils.getCookie(user)
        user['deviceId'] = Utils.getDeviceId(user)

    @staticmethod
    def getCpdailyExtension(user):
        info = {
            "systemName": "iOS",
            "systemVersion": "15.0",
            "model": "iPhone11,2",
            "deviceId": user['deviceId'],
            "appVersion": '9.0.12',
            "lon": user['lon'],
            "lat": user['lat'],
            "userId": user['username'],
        }
        return Utils.desEncrypt(json.dumps(info), DESKEY)

    @staticmethod
    def desEncrypt(s, key):
        iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        k = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        encrypt_str = k.encrypt(s)
        return base64.b64encode(encrypt_str).decode()

    @staticmethod
    def aesEncrypt(s, key, iv=b'\x01\x02\x03\x04\x05\x06\x07\x08\t\x01\x02\x03\x04\x05\x06\x07'):
        Encrypter = pyaes.Encrypter(
            pyaes.AESModeOfOperationCBC(key.encode('utf-8'), iv))
        Encrypted = Encrypter.feed(s)
        Encrypted += Encrypter.feed()
        return base64.b64encode(Encrypted).decode()


class SignTask:
    @staticmethod
    def getSignTaskInfo(user):
        header['Cookie'] = user['cookie']
        datas = json.loads(requests.post(
            url=TASKURL, json={}, headers=header).text)['datas']
        unSignedTasks = datas['unSignedTasks']
        for task in unSignedTasks:
            if '东北农业大学学生健康信息上报' in task['taskName']:
                return {'signInstanceWid': task['signInstanceWid'], 'signWid': task['signWid']}
        return {'signInstanceWid': -1, 'signWid': -1}

    @staticmethod
    def getDetailTask(user, signTaskInfo):
        header['Cookie'] = user['cookie']
        datas = json.loads(requests.post(url=DETAILTASKURL,
                           json=signTaskInfo, headers=header).text)['datas']
        return datas

    @staticmethod
    def getAnswerForm(user, detailTask):
        form = {}
        extraField = detailTask['extraField']
        form['signPhotoUrl'] = ''
        if detailTask['isNeedExtra']:
            form['isNeedExtra'] = 1
            extraFieldItemValues = []
            for item in extraField:
                extraFieldItems = item['extraFieldItems']
                for option in extraFieldItems:
                    if option['isAbnormal'] == False:
                        extraFieldItemValues.append(
                            {'extraFieldItemValue': option['value'], 'extraFieldItemWid': option['wid']})
                        break
            form['extraFieldItems'] = extraFieldItemValues
        form['longitude'] = user['lon']
        form['latitude'] = user['lat']
        form['isMalposition'] = detailTask['isMalposition']
        form['abnormalReason'] = ''
        form['signInstanceWid'] = detailTask['signInstanceWid']
        form['position'] = user['position']
        form['uaIsCpadaily'] = True
        form['signVersion'] = '1.0.0'
        return form

    @staticmethod
    def getBodyString(form):
        return Utils.aesEncrypt(json.dumps(form), AESKEY)

    @staticmethod
    def getSign(reqForm):
        form = {
            "appVersion": '9.0.12',
            "bodyString": reqForm['bodyString'],
            "deviceId": reqForm["deviceId"],
            "lat": reqForm["lat"],
            "lon": reqForm["lon"],
            "model": reqForm["model"],
            "systemName": reqForm["systemName"],
            "systemVersion": reqForm["systemVersion"],
            "userId": reqForm["userId"],
        }
        signStr = ''
        for info in form:
            if signStr:
                signStr += '&'
            signStr += "{}={}".format(info, form[info])
        signStr += "&{}".format(AESKEY)
        return hashlib.md5(signStr.encode()).hexdigest()

    @staticmethod
    def getReqForm(user, form):
        reqForm = {}
        reqForm['appVersion'] = '9.0.12'
        reqForm['systemName'] = "iOS"
        reqForm['bodyString'] = SignTask.getBodyString(form)
        reqForm['lon'] = form['longitude']
        reqForm['calVersion'] = 'firstv'
        reqForm['model'] = 'iPhone11,2'
        reqForm['systemVersion'] = '15.0'
        reqForm['deviceId'] = user['deviceId']
        reqForm['userId'] = user['username']
        reqForm['version'] = "first_v2"
        reqForm['lat'] = form['latitude']
        reqForm['sign'] = SignTask.getSign(reqForm)
        return reqForm


if __name__ == '__main__':
    for user in users:
        status = ''
        Utils.initStuInfo(user)
        if user['cookie'] == '':
            status = Utils.getTime() + '获取Cookie失败'
            print(user['username'] + ' ' + status)
            continue
        signTaskInfo = SignTask.getSignTaskInfo(user)
        if signTaskInfo['signWid'] == -1:
            status = Utils.getTime() + '无签到任务'
            print(user['username'] + ' ' + status)
            continue
        form = SignTask.getReqForm(user, SignTask.getAnswerForm(
            user, SignTask.getDetailTask(user, signTaskInfo)))
        liteHeader['Cookie'] = user['cookie']
        liteHeader['Cpdaily-Extension'] = Utils.getCpdailyExtension(user)
        resBody = json.loads(requests.post(
            url=LOGINURL, json=form, headers=liteHeader).text)
        if '任务未开始' in resBody['message']:
            status = Utils.getTime() + '任务未开始'
        else:
            status = Utils.getTime() + 'SUCCESS'
        print(user['username'] + ' ' + status)