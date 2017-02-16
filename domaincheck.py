# -*- coding:utf-8 -*-
#!/usr/bin/env python

"""
@version: V1
@author: Ron Chen
@software: PyCharm
@file: beianquery.py
@time: 2017/2/10 14:42
"""

import os, sys, requests, re, time, pytesser, Image, ImageFilter, ImageEnhance, urllib, urllib2, json, gevent
import configparser
from gevent import monkey; monkey.patch_all()   # 如果有IO操作时需要加上
from scrapy.selector import Selector
from apscheduler.schedulers.blocking import BlockingScheduler
# import scrapy
# from scrapy.http import Request

cur_path = os.path.abspath('.').replace('\\', '/')
config_path = cur_path + "/domaincheck.conf"
config_file = configparser.ConfigParser()

# 以下为脚本默认运行参数，若存在配置文件，则以配置文件中的配置为准，若配置文件不存在，则必须将以下参数配置正确，脚本会自动生成配置文件
# 配置文件中所有配置内容符合configparser要求，并所有的值要求符合json格式，否则将运行报错

SYSCONFIG = {
    "studymode": True,
    # "CHKICPAPIURL" = "http://beian.35.com/manager/Beianquery.aspx"
    "chkicpapiurl": {
        "35com": {"name":'三五互联', "url":"http://beian.35.com/manager/Query.aspx"}
    },
    "chkdomapiurl": {
        "chinazping": {"name":'站长之家', "url":"http://ping.chinaz.com/"}
    },
    "validatecodeurl": "http://beian.35.com/manager/ValidateCode.aspx",
    "picpath": sys.path[0].replace('\\', '/')+'/validatecode/',
    "reqinterval": 5,
    "reqtimeout": 60,
    "pingthreshold": 400,
    "alertline" : ['chinanet', 'unicom', 'netcom', 'multiline', 'mobile', 'railcom', 'other', 'oversea'],
    "receiver":{
        "weixin": ["sylekon"],
        "email": ["bullermartin@126.com"],
    },
    # Weichat Team
    "weixin": {
        "corpid": 'xxx',     # corpid是企业id
        "corpsecret": 'xxxx',   # corpsecret是企业密钥
        'toparty': '1',     # toparty否部门ID列表，多个接收者用‘|’分隔，最多支持100个。当touser为@all时忽略本参数
        'agentid': '0',     # agentid是企业应用的id，整型。可在应用的设置页面查看
        'safe': '1'         # safe否表示是否是保密消息，0表示否，1表示是，默认0
    },

    "email": {
        "host": '',
        "port": 0,
        "username": '',
        "password": '',
        "sender": '',
    }
}


DomainList = {
    # 测试域名
    "baidu": [["baidu.com",True]],
    "qq": [["qq.com",True]],
}


# 脚本默认运行参数结束

DomainIpList = {}

# 检查域名ICP备案信息, 通过反射 支持增加ICP查询接口
def CheckDomainICP():
    print(time.strftime("[%Y-%m-%d  %H:%M:%S] ") + "Check Domain ICP Info")
    try:
        checkdomicp =  CheckDomainICPAct()
        for project in DomainList.keys():
            project = project
            for dom in DomainList[project]:
                dom[0] = dom[0].lower()
                if len(dom) ==2 and IsDomain(dom):
                    # 若域名本身检查状态为False，如果已经备案 则发送提醒消息，并修改预定义值(暂未完善，需要将配置写入文件)
                    if not dom[1]:
                        continue

                    # 循环所有备案可用接口
                    for apisrc in SYSCONFIG["chkicpapiurl"].keys():
                        if hasattr(checkdomicp, "GetDomainICP_%s" % apisrc):
                            func = getattr(checkdomicp, "GetDomainICP_%s" % apisrc)
                        else:
                            raise "Don't have ICP Check API source like %s! Please check your ICP Check API source configuration!" % SYSCONFIG["chkicpapiurl"][apisrc]["name"]

                        icpres = func(dom[0], apisrc)
                        print(icpres)
                        if icpres["result"]:  # 如果已查到备案结果则退出循环
                            break
                    # 已查询到结果但没有备案的域名信息发送提醒消息
                    if not icpres["beian"] and icpres["result"]:
                        SendMessage(project, icpres, '备案信息报警')
                    time.sleep(SYSCONFIG["reqinterval"])
                else:
                    print("请检查%s项目域名列表！" % project)
                    continue
    except Exception as e:
            print(e)

class CheckDomainICPAct(object):
    def GetDomainICP_35com(self, domain='', apisrc=''):
        '''
        通过beian.35.com备案查询接口，模拟请求查询ICP备案
        :param domain:
        :return: result = {
                    "domain": domain,
                    "statuscode": request.status_code,
                    "beian": False,
                    "icpcode" : None,
                    "errormsg": ['', '']
                }
        '''
        domain = domain.strip()
        pic_name = "tmpcode.bmp"
        pic_path = SYSCONFIG["picpath"] + pic_name
        result = {}

        HEADER = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh,zh-CN;q=0.8,en-US;q=0.5,en;q=0.3",
            "Cache-Control": "no-cache" ,
            "Connection": "keep-alive",
            # "Cookie": "safedog-flow-item=; ASP.NET_SessionId=lujpqkgqg4flsjz5s4wxw3bk; CheckCode=XUMM",   # 在POST请求查询结果时必须有这个属性
            "Host": "beian.35.com",
            "Pragma": "no-cache",
            "Upgrade-Insecure-Requests": 1,
            "User-Agent": "Mozilla/8.0 (Windows NT 9; WOW64; rv:22.0) Gecko/20191223 Firefox/59.1"
        }
        COOKIES = {}

        # 发第一次请求主页面信息
        try:
            ret = requests.get(SYSCONFIG["chkicpapiurl"][apisrc]["url"], headers=HEADER, timeout=SYSCONFIG["reqtimeout"])
            COOKIES = ret.cookies
            ret.encoding = 'utf-8'
            hxs = Selector(text=ret.text)

        except Exception as e:
            result["result"] = False
            result["beian"] = False
            result["icpcode"] = None
            result["errormsg"] = ['', e]

        # 发第二次请求，重新获取验证码图片并保存到本地
        try:
            ret = requests.get(SYSCONFIG["validatecodeurl"], stream=True, cookies=COOKIES, headers=HEADER)
            COOKIES = ret.cookies
            with open(pic_path, 'wb') as f:
                for chunk in ret.iter_content(chunk_size=1024):
                    if chunk:  # filter out keep-alive new chunks
                        f.write(chunk)
                        f.flush()
                f.close()
        except Exception as e:
            result["result"] = False
            result["beian"] = False
            result["icpcode"] = None
            result["errormsg"] = ['', e]

        # 第三次请求查询结果，分析并打印结果
        try:
            # 获取验证码字符
            # vcode = GetCode(pic_path)
            vcode = COOKIES['CheckCode'].lower()

            # 构造POST请求数据
            viewstate = hxs.xpath('//*[@id="__VIEWSTATE"]/@value').extract()[0]
            viewstategeneractor = hxs.xpath('/html/body/form/div[2]/input/@value').extract()[0]
            POST_DATA = {
                'CheckCode':vcode,
                '__VIEWSTATE':viewstate,
                '__VIEWSTATEGENERATOR':viewstategeneractor,
                'btnSearch':'查询',
                'rbtnCheckType':0,   # 查询条件为网站域名
                'txtValue':domain
            }
            sessionid = ret.cookies.get("ASP.NET_SessionId")
            HEADER['Cookie'] = "safedog-flow-item=; ASP.NET_SessionId=%s; CheckCode=%s" % (ret.cookies.get("ASP.NET_SessionId"), vcode)

            # 发送POST查询请求
            ret = requests.post(SYSCONFIG["chkicpapiurl"][apisrc]["url"],data=POST_DATA,cookies=COOKIES,headers=HEADER)
            ret.encoding = 'utf-8'
            hxs = Selector(text=ret.text)
            res = hxs.xpath('//*[@id="lblRes"]/text()').extract()[0].strip().encode('utf-8')


            if "未备案" in res and ret.status_code == 200:
                result["result"] = True
                result["beian"] = False
                result["icpcode"] = None
                result["errormsg"] = ['', "未备案！"]
            elif "已备案" in res and ret.status_code == 200:
                result["result"] = True
                result["beian"] = True
                result["icpcode"] = res.split('：')[1]
                result["errormsg"] = ['', '']
            else:
                result["result"] = False
                result["beian"] = False
                result["icpcode"] = None
                result["errormsg"] = [ret.status_code, res]

        except Exception as e:
            result["result"] = False
            result["beian"] = False
            result["icpcode"] = None
            result["errormsg"] = ['', e]

        # 返回最终查询结果
        # if type(SYSCONFIG["chkicpapiurl"][apisrc]["name"]) == str:
        #     result["apisrc"] = SYSCONFIG["chkicpapiurl"][apisrc]["name"]
        # else:
        result["apisrc"] = SYSCONFIG["chkicpapiurl"][apisrc]["name"]
        result["domain"] = domain
        return result


# 检查DNS解析记录及Ping延时报警， 通过反射支持DNS查询接口
def CheckDNSRecoder():
    try:
        print(time.strftime("[%Y-%m-%d  %H:%M:%S] " + "Check Domain DNS Recoder"))
        for project in DomainList.keys():
            project = project
            for dom in DomainList[project]:
                dom[0] = dom[0].lower()
                if len(dom) ==2 and IsDomain(dom):
                    # 若域名本身检查状态为False，如果已经备案 则发送提醒消息，并修改预定义值(暂未完善，需要将配置写入文件)
                    # if not dom[1]:
                    #     continue

                    checkdns = CheckDNSRecoderAct()
                    checkdns.GetDNSRecoder(dom)
                    time.sleep(5)
                else:
                    print(dom)
                    print("Please Check the domain %s of Project %s!" % (dom[0], project))
                    continue

        print(DomainIpList)
    except Exception as e:
        print(e)

class CheckDNSRecoderAct(object):
    def __init__(self):
        self.result = {
            'iplist':[],
            'chinanet': {'name': '电信', 'num': 0, 'elapsed': 0},
            'unicom': {'name': '联通', 'num': 0, 'elapsed': 0},
            'multiline': {'name': '多线', 'num': 0, 'elapsed': 0},
            'mobile': {'name': '移动', 'num': 0, 'elapsed': 0},
            'railcom': {'name': '铁通', 'num': 0, 'elapsed': 0},
            'netcom': {'name': '网通', 'num': 0, 'elapsed': 0},
            'oversea': {'name': '海外', 'num': 0, 'elapsed': 0},
            'other': {'name': '其他', 'num': 0, 'elapsed': 0},
            'failed': 0,
            'succeed': 0
        }
        self.HEADER = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh,zh-CN;q=0.8,en-US;q=0.5,en;q=0.3",
            "Cache-Control": "no-cache" ,
            "Connection": "keep-alive",
            # "Cookie": "qHistory=aHR0cDovL3BpbmcuY2hpbmF6LmNvbStQaW5n5qOA5rWLfGh0dHA6Ly90b29sLmNoaW5hei5jb20vZG5zLytEbnPmn6Xor6J8ZmluZC8r5om+5Zue5aSH5qGI5a+G56CBfHJlcG9ydC8r5o6l5YWl5ZWG5p+l6K+ifGh0dHA6Ly9pY3AuY2hpbmF6LmNvbS8r572R56uZ5aSH5qGI; nping=host=baidu.com",   # 在POST请求查询结果时必须有这个属性
            "Host": "ping.chinaz.com",
            "Pragma": "no-cache",
            "Upgrade-Insecure-Requests": 1,
            "Referer": "http://ping.chinaz.com/",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0",
            "X-Requested-With": "XMLHttpRequest"
        }
        self.COOKIES = {}

    def GetDNSRecoder(self, dom):
        try:
            # 循环所有可用查询接口
            for apisrc in SYSCONFIG["chkdomapiurl"].keys():
                if hasattr(self, "GetDnsRecorder_%s" % apisrc):
                    func = getattr(self, "GetDnsRecorder_%s" % apisrc)
                else:
                    raise "Don't have Domain Check API source like %s! Please check your Domain Check API source configuration!" % SYSCONFIG["chkdomapiurl"][apisrc]["name"]
                dnsres = func(dom[0], apisrc)

                # 获取到某个域名检查结果后的操作
                if SYSCONFIG['studymode']:  # 只有在学习模式时才学习域名IP地址列表
                    if dom[0] in DomainIpList.keys():
                        DomainIpList[dom[0].replace('.', '')] = list(set(self.result['iplist'] + DomainIpList[dom[0].replace('.', '')]))
                    else:
                        DomainIpList[dom[0].replace('.', '')] = list(set(self.result['iplist']))
                    # 本域名本次IP地址学习完毕，将结果保存至配置文件
                    if os.path.isfile(config_path):
                        config_file.read(config_path)
                        if not config_file.has_section('DomainIpList'):
                            config_file.add_section('DomainIpList')
                        for k, v in DomainIpList.items():
                            if config_file.has_option('DomainIpList', k):
                                temp_iplist = json.loads(config_file['DomainIpList'][k]) + DomainIpList[k]
                                config_file.set('DomainIpList', k, json.dumps(temp_iplist))
                            config_file.set('DomainIpList', k, json.dumps(v))
                        config_file.write(open(config_path, "w"))

                        # 写入完毕后，重新加载配置文件
                        LoadConfiguration()
                    else:
                        print("Found new ip address, but faild when write configuration in to file fail!")
                else:   # 非学习模式时，需要检查是否在解析出的IP不在可信IP列表中
                    for ip in self.result['iplist']:  # 循环判断Ping结果IP是否在可信IP列表中
                        if dom[0].replace('.', '') in DomainIpList.keys():
                            if ip in DomainIpList[dom[0].replace('.', '')]:
                                continue
                            else:
                                print('Discover abnormal ip: %s of Domain: %s' % (ip, dom[0]))
                                message = '发现异常IP！ 域名:%s IP:%s' % (dom[0], ip)
                                gevent.joinall([
                                    gevent.spawn(SendToWeichat, message, 'Ping检测发现异常IP'),   # 发送微信消息
                                    gevent.spawn(SendToEmail, SYSCONFIG["email"]["sender"], SYSCONFIG["receiver"]["email"], 'Ping检测发现异常IP', message)   # 发送邮件
                                ])
                        else:
                            print ("Haven't found domain %s in trusted ip list!  Abnormal IP: %s " % (dom[0], ip))
                            continue

                # 根据ping检查结果判断响应时间是否需要报警
                print(self.result)
                message = '域名:%s ' % dom[0]
                alert = False
                for k, v in self.result.items():
                    if k in SYSCONFIG['alertline'] and self.result[k]['num'] > 0:
                        pingavg = self.result[k]['elapsed']/self.result[k]['num']
                        if pingavg >= SYSCONFIG['pingthreshold']:
                            alert = True
                        message += self.result[k]['name'] + ':%dms ' % pingavg
                    else:
                        print('Can not find line name or no checkpoint returned data! Line Name:%s' % k)

                if alert:
                    gevent.joinall([
                        gevent.spawn(SendToWeichat, message, '域名Ping检测'),   # 发送微信消息
                        gevent.spawn(SendToEmail, SYSCONFIG["email"]["sender"], SYSCONFIG["receiver"]["email"], '域名Ping检测', message)   # 发送邮件
                    ])

                # # 已查询到结果但没有备案的域名信息发送提醒消息
                # if not dnsres["beian"] and dnsres["result"]:
                #     SendMessage(project, dnsres, '备案信息报警')
                time.sleep(SYSCONFIG["reqinterval"])
        except Exception as e:
            print(e)

    def GetDnsRecorder_chinazping(self, domain='', apisrc=''):
        '''
        通过Chinaz提供的Ping域名接口，抓取接口调用后页面信息
        :param domain:
        :param apisrc:
        :return:result{}
        '''

        # 发第一次请求主页面信息
        try:
            ret = requests.get(SYSCONFIG["chkdomapiurl"][apisrc]["url"] + domain, headers=self.HEADER, timeout=SYSCONFIG["reqtimeout"])
            self.COOKIES = ret.cookies
            ret.encoding = 'utf-8'
            # print(ret.text)
            hxs = Selector(text=ret.text)
            chkpointnum = len(hxs.xpath("/html/body/div[2]/div/div[2]/ul/li[position()>1]"))
            self.result["chkpointnum"] = chkpointnum
            # print(chkpointnum)

            # 启动协程并发获取所有解析出来的IP，并保存到self.result['iplist]
            splist = []
            for cpn in range(2, chkpointnum+2):
                # print(cpn)
                # if cpn % 3 == 0:
                #     time.sleep(3)
                splist.append(gevent.spawn(self.GetChkPointRes, hxs, domain, cpn))
            gevent.joinall(splist)

            # 本次学习IP地址及检测ping延时结束，开始保存结果
            # print(self.result)
            return self.result

        except Exception as e:
            print("Cann't get anything from api:%s!  Error:%s" % (SYSCONFIG["chkdomapiurl"][apisrc]['name'], e))
            return

    def GetChkPointRes(self, hxs, domain, cpn):
        try:
            # 获取检查点的guid，并构造POST_DATA发起第二次POST请求获取检查结果
            cpguid = hxs.xpath("/html/body/div[2]/div/div[2]/ul/li[%d]/@id" % cpn).extract()
            # 获取encode
            encode = hxs.xpath("/html/body/input[1]/@value").extract()[0]
            city = hxs.xpath("/html/body/div[2]/div/div[2]/ul/li[%d]/span[1]/text()" % cpn).extract()[0]
            # print(encode)
            # POST检查请求示例http://ping.chinaz.com/ajaxseo.aspx?t=ping&callback=jQuery1113009497356425168157_1486971980598
            POST_DATA = {
                "checktype": "0",
                "encode": encode,
                "guid": cpguid,
                "host": domain,
                "ishost": "0"
            }

            r = requests.post("http://ping.chinaz.com/iframe.ashx?t=ping", data=POST_DATA, headers=self.HEADER, cookies=self.COOKIES, timeout=SYSCONFIG["reqtimeout"])
            if r.status_code != 200 or "state:0" in r.text.replace(' ', ''):
                self.result['failed'] += 1
                return

            # print(json.loads(u'{state:"1",msg:"",result:{ip:"125.39.240.113",ipaddress:"天津市 腾讯公司联通数据中心",responsetime:"25毫秒",ttl:"52",bytes:"32"}}'.decode()))
            response = r.text[1:-1].replace('\'', '\"')  #.replace("\\", "\\\\")
            response = response.replace("state", "\"state\"").replace("msg", "\"msg\"").replace("ipaddress","\"ipaddress\"")
            response = response.replace("ip:", "\"ip\":").replace("ttl", "\"ttl\"").replace("bytes","\"bytes\"")
            response = response.replace("result", "\"result\"").replace("responsetime", "\"responsetime\"").replace("error", "\"error\"")
            response = str(repr(response)).replace("u\'", "").replace("\'", "")
            response = json.loads(response)

            for k,v in response.items():
                if k == 'result':
                    continue
                response[k] = str(v)
            for k,v in response['result'].items():
                response['result'][k] = str(v.encode(encoding='utf-8'))

            if '超时' in response['result']['ip']:
                self.result['failed'] += 1
                return False
            elif response['result']['ip'] in self.result['iplist']:
                self.AnalyzeRes(response, hxs, cpn)
            else:
                # print(response['result']['ip'] + ' ' + city)
                self.result['iplist'].append(response['result']['ip'])
                self.AnalyzeRes(response, hxs, cpn)
            return True
        except Exception as e:
            print(self.result)
            print("Get ping result failed! Error:%s" % e)
            return False

    def AnalyzeRes(self, response, hxs, cpn):
        '''
        拆分获取到的运营商及访问耗时结果，并将结果汇总到self.result中
        :param response:
        :return:
        '''

        try:
            localinfo = hxs.xpath("/html/body/div[2]/div/div[2]/ul/li[%d]/span[1]/text()" % cpn).extract()[0].encode(encoding='utf-8')
            if '超时' not in response['result']['responsetime'] and '-' not in response['result']['responsetime']:
                responsetime = int(re.findall('\d+', response['result']['responsetime'])[0])

                if '电信' in localinfo:
                    self.result['chinanet']['num'] += 1
                    self.result['chinanet']['elapsed'] += responsetime
                elif '联通' in localinfo:
                    self.result['unicom']['num'] += 1
                    self.result['unicom']['elapsed'] += responsetime
                elif '多线' in localinfo:
                    self.result['multiline']['num'] += 1
                    self.result['multiline']['elapsed'] += responsetime
                elif '移动' in localinfo:
                    self.result['mobile']['num'] += 1
                    self.result['mobile']['elapsed'] += responsetime
                elif '铁通' in localinfo:
                    self.result['railcom']['num'] += 1
                    self.result['railcom']['elapsed'] += responsetime
                elif '网通' in localinfo:
                    self.result['netcom']['num'] += 1
                    self.result['netcom']['elapsed'] += responsetime
                elif '海外' in localinfo:
                    self.result['oversea']['num'] += 1
                    self.result['oversea']['elapsed'] += responsetime
                else:
                    self.result['other']['num'] += 1
                    self.result['other']['elapsed'] += responsetime
                self.result['succeed'] += 1
                return True
            else:
                self.result['failed'] += 1
                return False
        except Exception as e:
            print(e)

def IsDomain(dom=[]):
    # 检查域名是否符合正确格式
    if type(dom[1]) == bool:
        if re.search('^([a-zA-Z0-9]+-*\.)+[a-zA-Z]{2,}$', dom[0].strip()):
            return True
    return False

def SendMessage(project='', icpres='', title=''):
    message = "项目: %s  域名: %s  错误:%s  来源: %s" % (project, icpres['domain'], icpres['errormsg'][1], icpres['apisrc'])
    # 启动协程发送报警消息
    gevent.joinall([
        gevent.spawn(SendToWeichat, message, title),   # 发送微信消息
        gevent.spawn(SendToEmail, SYSCONFIG["email"]["sender"], SYSCONFIG["receiver"]["email"], title, message)   # 发送邮件
    ])

def SendToWeichat(message='', title=''):
    """
    touser否成员ID列表（消息接收者，多个接收者用‘|’分隔，最多支持1000个）。特殊情况：指定为@all，则向关注该企业应用的全部成员发送
    toparty否部门ID列表，多个接收者列表，最多支持100个。当touser为@all时忽略本参数
    totag否标签ID列表，多个接收者用‘|’分隔。当touser为@all时忽略本参数
    msgtype是消息类型，此时固定为：text
    agentid是企业应用的id，整型。可在应用的设置页面查看
    message是消息内容
    safe否表示是否是保密消息，0表示否，1表示是，默认0
    """

    # baseurl = 'https://qyapi.weixin.qq.com/cgi-bin/gettoken'
    # securl = 'https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%s' % access_token
    class WeChatMSG(object):
        def __init__(self,touser, corpid, corpsecret, toparty, agentid, title, message):
            self.gettoken_url = 'https://qyapi.weixin.qq.com/cgi-bin/gettoken'
            self.gettoken_content = {
                                'corpid' : corpid,
                                'corpsecret' : corpsecret,
                                }
            self.main_content = {
                                "touser": touser,
                                "toparty":toparty,
                                "agentid":agentid,
                                "msgtype": "text",
                                # "safe": str(safe),
                                "title": title,
                                "text":{
                                    "content":message,
                                        }
                                }

        def get_access_token(self,string):
            token_result = json.loads(string.read())
            access_token=  token_result['access_token']
            return access_token.encode('utf-8')
        def geturl(self,url,data):
            data = self.encodeurl(data)
            response = urllib2.urlopen('%s?%s' % (url,data))
            return response.read().decode('utf-8')
        def posturl(self,url,data,isjson = True):
            if isjson:
                data = json.dumps(data, ensure_ascii=False)     # 加上参数ensure_ascii=False 后 提交的数据中的中文就不会再被转码
            # 方法一 无效
            # response = urllib2.urlopen(url,data)
            # return response.read().decode('utf-8')

            # 方法二 无效
            # req = urllib2.Request(url)
            # req.add_header('Content-Type', 'application/json')
            # req.add_header('encoding', 'utf-8')
            # response = urllib2.urlopen(req, data)
            # return response.read().decode('utf-8')

            # 方法三 正常
            response = requests.post(url,data)
            # print(response.text)
            return response.text
        def encodeurl(self,dict):
            data = ''
            for k,v in dict.items():
                data += '%s=%s%s' % (k,v,'&')
            return data

    touser = SYSCONFIG["receiver"]["weixin"]
    msgsender = WeChatMSG(touser=touser,
                          corpid=SYSCONFIG["weixin"]["corpid"],
                          corpsecret=SYSCONFIG["weixin"]["corpsecret"],
                          toparty=SYSCONFIG["weixin"]["toparty"],
                          agentid=SYSCONFIG["weixin"]["agentid"],
                          title=title,
                          message=message,)

    access_token_response = msgsender.geturl(msgsender.gettoken_url, msgsender.gettoken_content)
    access_token =  json.loads(access_token_response)['access_token']
    sendmsg_url = 'https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%s' % access_token
    result = msgsender.posturl(sendmsg_url,msgsender.main_content)
    if json.loads(result) == json.loads('{"errcode":0,"errmsg":"ok"}'):
        return 0
    else:
        print(result)

def SendToEmail(sender='', receiver=[], subject='', message=''):
    try:
        import smtplib
        from email.mime.text import MIMEText

        if len(sender) ==  0 or len(receiver) == 0 or len(subject) == 0 or len(message) == 0:
            raise "Please Check Email server configuration!"

        msg = MIMEText(message,'html','utf-8')
        msg['Subject'] = subject

        smtp = smtplib.SMTP()
        smtp.connect(host=SYSCONFIG["email"]["host"], port=int(SYSCONFIG["email"]["port"]))
        smtp.login(SYSCONFIG["email"]["username"], SYSCONFIG["email"]["password"])

        # 循环receiver列表发送邮件
        for rev in receiver:
            try:
                if re.search('^[0-9a-zA-Z]+-?@([a-zA-Z0-9]+-*\.)+[a-zA-Z]{2,}', rev):
                    smtp.sendmail(sender, rev, msg.as_string())
                    time.sleep(5)
                else:
                    raise "Email receiver format error!"
            except Exception as e:
                print(e)
        smtp.quit()
    except Exception as e:
        print("Send Email faild!  ERROR! %s" % e)

class ConvertAnyToStr(object):
    '''
    将任意接收到的类型unicode值转换为最基础的UTF-8编码字符串
    :param s:
    :return:
    '''

    def dictToStr(self,dic):
        tmpdic = {}
        for k,v in dic.items():
            if type(v) == list:
                tmpdic[str(k)] = self.listToStr(v)
                continue
            elif type(v) == dict:
                tmpdic[str(k)] = self.dictToStr(v)
                continue
            else:
                tmpdic[str(k)] = self.unicodeToStr(v)
        return tmpdic
    def listToStr(self, li):
        for i in range(0, len(li)):
            # print(type(li[i]), li[i])
            if isinstance(li[i], list):
                li[i] = self.listToStr(li[i])
            elif isinstance(li[i], dict):
                li[i] = self.dictToStr(li[i])
            elif isinstance(li[i], unicode):
                li[i] = self.unicodeToStr(li[i])

        return li
    def unicodeToStr(self, u):
        if type(u) == unicode:
            return str(u.encode(encoding='utf-8')).strip()
        else:
            return u
    def returnAny(self, any):
        if type(any) == dict:
            return self.dictToStr(any)
        elif type(any) == list:
            return self.listToStr(any)
        elif type(any) == str:
            return self.unicodeToStr(any)
        return any

def LoadConfiguration():
    try:
        print("loading configuration......")
        if os.path.isfile(config_path):
            config_file.read(config_path)
            SYSCONFIG = {}
            DomainList = {}
            DomainIpList = {}
            for sec in config_file.sections():
                if sec == 'SystemConfig':
                    for k, v in config_file[sec].items():
                        SYSCONFIG[str(k)] = json.loads(v)
                elif sec == 'DomainList':
                    for k, v in config_file[sec].items():
                        DomainList[str(k)] = json.loads(v)
                elif sec == 'DomainIpList':
                    for k, v in config_file[sec].items():
                        DomainIpList[str(k)] = json.loads(v)
        else:
            # 当配置文件不存在时， 应将脚本最上方的配置以字典的形式补充完整，否则将会报错
            config_file.add_section('SystemConfig')
            config_file.add_section('DomainList')
            config_file.add_section('DomainIpList')
            for (k,v) in SYSCONFIG.items():
                config_file.set('SystemConfig', k, json.dumps(v))
            for k,v in DomainList.items():
                config_file.set('DomainList', k, json.dumps(v))
            config_file.write(open(config_path, "w"))
        print("Loading configuration success!")
    except Exception as e:
        print('Loading running configuration failed!  Error: %s' % e)
        sys.exit()

    # 处理Unicode值，将所有遇到的unicode字符串值转换为UTF-8编码字符串
    SYSCONFIG = ConvertAnyToStr().returnAny(SYSCONFIG)
    DomainList = ConvertAnyToStr().returnAny(DomainList)
    DomainIpList = ConvertAnyToStr().returnAny(DomainIpList)

if __name__ == "__main__":

    #加载配置文件
    LoadConfiguration()

    # 启动任务定时器
    try:
        print('Program is running.....')
        sched = BlockingScheduler()
        # CheckDomainICP()
        # CheckDNSRecoder()
        sched.add_job(CheckDomainICP, 'cron', minute='*/20')
        sched.add_job(CheckDNSRecoder, 'cron', minute='*/20')
        try:
            sched.start()
        except (KeyboardInterrupt, SystemExit) as e:
            print(e)
            sched.shutdown()
        # GetDomainICP()
        print('Program is stoped.....')
    except Exception as e:
        print('Program is stoped! Error: %s' % e)
