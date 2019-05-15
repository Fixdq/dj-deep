# -*- coding: utf-8 -*-
"""
Created on 2014-5-13

@author: skycrab
"""
import json
import time
import random
import string
import urllib
import hashlib
import threading
import traceback
import xml.etree.ElementTree as ET
import logging
from urllib import request as urllib2

from functools import wraps

from .config import WxPayConf, WxPayConf_shop

try:
    import pycurl
    from cStringIO import StringIO
except ImportError:
    pycurl = None

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger('control')


def catch(func):
    @wraps(func)
    def wrap(*args,**kwargs):
        try:
            return func(*args,**kwargs)
        except Exception as e:
            print(traceback.format_exc())
            return None
    return wrap


class ObjectDict(dict):
    """Makes a dictionary behave like an object, with attribute-style access.
    """
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value


class Singleton(object):
    """可配置单例模式"""

    _instance_lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, "_instance"):
            with cls._instance_lock:
                if not hasattr(cls, "_instance"):
                    impl = cls.configure() if hasattr(cls, "configure") else cls
                    instance = super(Singleton, cls).__new__(impl, *args, **kwargs)
                    if not isinstance(instance, cls):
                        instance.__init__(*args, **kwargs)
                    cls._instance = instance
        return cls._instance


class class_property(object):
    """ A property can decorator class or instance

    class Foo(object):
        @class_property
        def foo(cls):
            return 42


    print(Foo.foo)
    print(Foo().foo)

    """
    def __init__(self, func, name=None, doc=None):
        self.__name__ = name or func.__name__
        self.__module__ = func.__module__
        self.__doc__ = doc or func.__doc__
        self.func = func

    def __get__(self, obj, type=None):
        value = self.func(type)
        return value


class BaseHttpClient(object):
    include_ssl = False

    def get(self, url, second=30):
        if self.include_ssl:
            return self.postXmlSSL(None, url, second, False, post=False)
        else:
            return self.postXml(None, url, second)

    def postXml(self, xml, url, second=30):
        if self.include_ssl:
            return self.postXmlSSL(xml, url, second, cert=False)
        else:
            raise NotImplementedError("please implement postXML")

    def postXmlSSL(self, xml, url, second=30, cert=True, cert_path=WxPayConf.SSLCERT_PATH,
                   key_path=WxPayConf.SSLKEY_PATH, post=True):
        raise NotImplementedError("please implement postXMLSSL")


class UrllibClient(BaseHttpClient):
    """使用urlib2发送请求"""
    def postXml(self, xml, url, second=30):
        """不使用证书"""
        data = urllib2.urlopen(url, xml, timeout=second).read()
        return data


class CurlClient(BaseHttpClient):
    """使用Curl发送请求"""
    include_ssl = True

    def __init__(self):
        self.curl = pycurl.Curl()
        self.curl.setopt(pycurl.SSL_VERIFYHOST, False)
        self.curl.setopt(pycurl.SSL_VERIFYPEER, False)
        # 设置不输出header
        self.curl.setopt(pycurl.HEADER, False)

    def postXmlSSL(self, xml, url, second=30, cert=True, cert_path=WxPayConf.SSLCERT_PATH,
                   key_path=WxPayConf.SSLKEY_PATH, post=True):
        """使用证书"""
        self.curl.setopt(pycurl.URL, url)
        self.curl.setopt(pycurl.TIMEOUT, second)
        # 设置证书
        # 使用证书：cert 与 key 分别属于两个.pem文件
        # 默认格式为PEM，可以注释
        if cert:
            self.curl.setopt(pycurl.SSLKEYTYPE, "PEM")
            self.curl.setopt(pycurl.SSLKEY, key_path)
            self.curl.setopt(pycurl.SSLCERTTYPE, "PEM")
            self.curl.setopt(pycurl.SSLCERT, cert_path)
        # post提交方式
        if post:
            self.curl.setopt(pycurl.POST, True)
            self.curl.setopt(pycurl.POSTFIELDS, xml)
        buff = StringIO()
        self.curl.setopt(pycurl.WRITEFUNCTION, buff.write)

        self.curl.perform()
        return buff.getvalue()


class RequestsClient(BaseHttpClient):
    include_ssl = True

    def postXmlSSL(self, xml, url, second=30, cert=True,
                   cert_path=WxPayConf.SSLCERT_PATH, key_path=WxPayConf.SSLKEY_PATH, post=True):
        if cert:
            cert_config = (cert_path, key_path)
        else:
            cert_config = None
        if post:
            # res = requests.post(url, data=xml, second=30, cert=cert_config)
            res = requests.post(url, data=xml, cert=cert_config)
        else:
            res = requests.get(url, timeout=second, cert=cert_config)
        return res.content


class HttpClient(Singleton, BaseHttpClient):

    @classmethod
    def configure(cls):
        config_client = WxPayConf.HTTP_CLIENT
        client_cls = {"urllib": UrllibClient,
                      "curl": CurlClient,
                      "requests": RequestsClient}.get(config_client.lower(), None)
        if client_cls:
            return client_cls

        if pycurl is not None:
            print("HTTP_CLIENT config error, Use 'CURL'")
            return CurlClient
        if requests is not None:
            print("HTTP_CLIENT config error, Use 'REQUESTS'")
            return RequestsClient
        else:
            print("HTTP_CLIENT config error, Use 'URLLIB'")
            return UrllibClient


class WeixinHelper(object):
    @classmethod
    def checkSignature(cls, signature, timestamp, nonce):
        """微信对接签名校验"""
        tmp = [WxPayConf.TOKEN, timestamp, nonce]
        tmp.sort()
        code = hashlib.sha1("".join(tmp)).hexdigest()
        return code == signature

    @classmethod
    def nonceStr(cls, length):
        """随机数"""
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

    @classmethod
    def xmlToArray(cls, xml):
        """将xml转为array"""
        return dict((child.tag, child.text) for child in ET.fromstring(xml))

    @classmethod
    def oauth2(cls, redirect_uri, scope="snsapi_userinfo", state="STATE"):
        """网页授权获取用户信息
        http://mp.weixin.qq.com/wiki/17/c0f37d5704f0b64713d5d2c37b468d75.html
        """
        _OAUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize?appid={0}&redirect_uri={1}&response_type=code&scope={2}&state={3}#wechat_redirect"
        return _OAUTH_URL.format(WxPayConf.APPID, urllib.quote(redirect_uri, safe=''), scope, state)

    @classmethod
    def proxy(cls, redirect_uri, scope="snsapi_userinfo", state="STATE", device="mobile"):
        """网页授权获取用户信息
        http://mp.weixin.qq.com/wiki/17/c0f37d5704f0b64713d5d2c37b468d75.html
        """
        _PROXY_URL = "http://shop.xuemei99.com/open/proxy?redirect_uri={0}&scope={1}&state={2}&device={3}"
        return _PROXY_URL.format(urllib.quote(redirect_uri, safe=''), scope, state, device)


    @classmethod
    def getAccessToken(cls, appid=WxPayConf.APPID, secret=WxPayConf.APPSECRET):
        """获取access_token
        需要缓存access_token,由于缓存方式各种各样，不在此提供
        http://mp.weixin.qq.com/wiki/11/0e4b294685f817b95cbed85ba5e82b8f.html
        """
        _ACCESS_URL = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={0}&secret={1}"
        return HttpClient().get(_ACCESS_URL.format(appid, secret))

    @classmethod
    def getShopAccessToken(cls):
        """获取access_token
        需要缓存access_token,由于缓存方式各种各样，不在此提供
        http://mp.weixin.qq.com/wiki/11/0e4b294685f817b95cbed85ba5e82b8f.html
        """
        _ACCESS_URL = "http://shop.xuemei99.com/open/access_token?format=json"
        return HttpClient().get(_ACCESS_URL)

    @classmethod
    def getUserInfo(cls, access_token, openid, lang="zh_CN"):
        """获取用户基本信息
        http://mp.weixin.qq.com/wiki/14/bb5031008f1494a59c6f71fa0f319c66.html
        """
        _USER_URL = "https://api.weixin.qq.com/cgi-bin/user/info?access_token={0}&openid={1}&lang={2}"
        return HttpClient().get(_USER_URL.format(access_token, openid, lang))

    @classmethod
    def getUserInfoBatch(cls, data, access_token):
        """批量获取用户基本信息
        http://mp.weixin.qq.com/wiki/1/8a5ce6257f1d3b2afb20f83e72b72ce9.html
        """
        _USER_URL = "https://api.weixin.qq.com/cgi-bin/user/info/batchget?access_token={0}"
        return HttpClient().postXml(data, _USER_URL.format(access_token))

    @classmethod
    def getAccessTokenByCode(cls, code):
        """通过code换取网页授权access_token, 该access_token与getAccessToken()返回是不一样的
        http://mp.weixin.qq.com/wiki/17/c0f37d5704f0b64713d5d2c37b468d75.html
        """
        _CODEACCESS_URL = "https://api.weixin.qq.com/sns/oauth2/access_token?appid={0}&secret={1}&code={2}&grant_type=authorization_code"
        url = _CODEACCESS_URL.format(WxPayConf.APPID, WxPayConf.APPSECRET, code)
        return HttpClient().get(url)

    @classmethod
    def getShopAccessTokenByCode(cls, code):
        """通过code换取网页授权access_token, 该access_token与getAccessToken()返回是不一样的
        http://mp.weixin.qq.com/wiki/17/c0f37d5704f0b64713d5d2c37b468d75.html
        """
        _CODEACCESS_URL = "https://api.weixin.qq.com/sns/oauth2/access_token?appid={0}&secret={1}&code={2}&grant_type=authorization_code"
        url = _CODEACCESS_URL.format(WxPayConf_shop.APPID, WxPayConf_shop.APPSECRET, code)
        return HttpClient().get(url)

    @classmethod
    def refreshAccessToken(cls, refresh_token):
        """刷新access_token, 使用getAccessTokenByCode()返回的refresh_token刷新access_token，可获得较长时间有效期
        http://mp.weixin.qq.com/wiki/17/c0f37d5704f0b64713d5d2c37b468d75.html
        """
        _REFRESHTOKRN_URL = "https://api.weixin.qq.com/sns/oauth2/refresh_token?appid={0}&grant_type=refresh_token&refresh_token={1}"
        return HttpClient().get(_REFRESHTOKRN_URL.format(WxPayConf.APPID, refresh_token))

    @classmethod
    def getSnsapiUserInfo(cls, access_token, openid, lang="zh_CN"):
        """拉取用户信息(通过网页授权)
        """
        _SNSUSER_URL = "https://api.weixin.qq.com/sns/userinfo?access_token={0}&openid={1}&lang={2}"
        return HttpClient().get(_SNSUSER_URL.format(access_token, openid, lang))

    @classmethod
    def getAccessTokenValid(cls, access_token, openid):
        """检测access_token是否过期"""
        _ACCESSTOKEN_VALID_URL = 'https://api.weixin.qq.com/sns/auth?access_token={0}&openid={1}'
        return HttpClient().get(_ACCESSTOKEN_VALID_URL.format(access_token, openid))

    @classmethod
    def getMaterialList(cls, data, access_token):
        """发送客服消息
        http://mp.weixin.qq.com/wiki/1/70a29afed17f56d537c833f89be979c9.html
        """
        _SEND_URL ="https://api.weixin.qq.com/cgi-bin/material/batchget_material?access_token={0}"
        data = json.dumps(data, ensure_ascii=False)
        return HttpClient().postXml(data, _SEND_URL.format(access_token))

    @classmethod
    def sendMsgAll(cls, data, access_token):
        """发送客服消息
        http://mp.weixin.qq.com/wiki/1/70a29afed17f56d537c833f89be979c9.html
        """
        _SEND_URL ="https://api.weixin.qq.com/cgi-bin/message/mass/sendall?access_token={0}"
        data = json.dumps(data, ensure_ascii=False)
        return HttpClient().postXml(data, _SEND_URL.format(access_token))

    @classmethod
    def send(cls, data, access_token):
        """发送客服消息
        http://mp.weixin.qq.com/wiki/1/70a29afed17f56d537c833f89be979c9.html
        """
        _SEND_URL ="https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token={0}"
        data = json.dumps(data, ensure_ascii=False)
        return HttpClient().postXml(data, _SEND_URL.format(access_token))

    @classmethod
    def sendTemplateMsg(cls, data, access_token):
        """发送模版消息
        http://mp.weixin.qq.com/wiki/1/70a29afed17f56d537c833f89be979c9.html
        """
        _SEND_URL ="https://api.weixin.qq.com/cgi-bin/message/template/send?access_token={0}"
        data = json.dumps(data, ensure_ascii=False)
        return HttpClient().postXml(data, _SEND_URL.format(access_token))

    @classmethod
    def getTextMessage(cls, openid, message):
        data = {
            "touser": openid,
            "msgtype":"text",
            "text":
            {
                "content": message
            }
        }
        return data

    @classmethod
    def sendTextMessage(cls, openid, message, access_token):
        """发送文本消息
        """
        data = {
            "touser": openid,
            "msgtype":"text",
            "text":
            {
                "content": message
            }
        }
        return cls.send(data, access_token)

    @classmethod
    def getJsapiTicket(cls, access_token):
        """获取jsapi_tocket
        """
        _JSAPI_URL = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token={0}&type=jsapi"
        return HttpClient().get(_JSAPI_URL.format(access_token))

    @classmethod
    def jsapiSign(cls, jsapi_ticket, url):
        """jsapi_ticket 签名"""
        sign = {
            'nonceStr': cls.nonceStr(15),
            'jsapi_ticket': jsapi_ticket,
            'timestamp': int(time.time()),
            'url': url
        }
        signature = '&'.join(['%s=%s' % (key.lower(), sign[key]) for key in sorted(sign)])
        sign["signature"] = hashlib.sha1(signature).hexdigest()
        return sign

    @classmethod
    def long2short(cls, long_url, access_token):
        """长链接转短链接
        https://mp.weixin.qq.com/wiki/6/856aaeb492026466277ea39233dc23ee.html
        """
        _SEND_URL = "https://api.weixin.qq.com/cgi-bin/shorturl?access_token={0}"
        data = json.dumps({'long_url': long_url, 'action': 'long2short'}, ensure_ascii=False)
        return HttpClient().postXml(data, _SEND_URL.format(access_token))

    @classmethod
    def getComponentAccessToken(cls, app_id, app_secret, ticket):
        """开放平台--获取component access token"""
        _COMPONENT_URL = "https://api.weixin.qq.com/cgi-bin/component/api_component_token"
        data = json.dumps({'component_appid': app_id, 'component_appsecret': app_secret, 'component_verify_ticket': ticket}, ensure_ascii=False)
        return HttpClient().postXml(data, _COMPONENT_URL)

    @classmethod
    def getPreAuthCode(cls, app_id, component_access_token):
        """开放平台--获取预授权码"""
        _PRE_AUTH_CODE_URL = "https://api.weixin.qq.com/cgi-bin/component/api_create_preauthcode?component_access_token={0}"
        data = json.dumps({'component_appid': app_id}, ensure_ascii=False)
        return HttpClient().postXml(data, _PRE_AUTH_CODE_URL.format(component_access_token))

    @classmethod
    def getQueryAuth(cls, app_id, code, component_access_token):
        """开放平台--使用授权码换取公众号的接口调用凭据和授权信息"""
        _QUERY_AUTH_URL = "https://api.weixin.qq.com/cgi-bin/component/api_query_auth?component_access_token={0}"
        data = json.dumps({'component_appid': app_id, 'authorization_code': code}, ensure_ascii=False)
        return HttpClient().postXml(data, _QUERY_AUTH_URL.format(component_access_token))

    @classmethod
    def getAuthorizerToken(cls, component_access_token, component_appid, authorizer_appid, authorizer_refresh_token):
        """开放平台--获取公众号接口调用token"""
        _AUTH_TOKEN_URL = "https://api.weixin.qq.com/cgi-bin/component/api_authorizer_token?component_access_token={0}"
        data = json.dumps({'component_appid': component_appid, 'authorizer_appid': authorizer_appid, 'authorizer_refresh_token': authorizer_refresh_token}, ensure_ascii=False)
        return HttpClient().postXml(data, _AUTH_TOKEN_URL.format(component_access_token))

    @classmethod
    def getAuthInfo(cls, app_id, auth_app_id, component_access_token):
        """开放平台--获取授权方的公众号帐号基本信息"""
        _AUTH_INFO_URL = "https://api.weixin.qq.com/cgi-bin/component/api_get_authorizer_info?component_access_token={0}"
        data = json.dumps({'component_appid': app_id, 'authorizer_appid': auth_app_id}, ensure_ascii=False)
        return HttpClient().postXml(data, _AUTH_INFO_URL.format(component_access_token))

    @classmethod
    def openOauth2(cls, app_id, c_app_id, redirect_uri, scope="snsapi_userinfo", state="STATE"):
        """开放平台--网页授权获取code
        https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1419318590&token=&lang=zh_CN
        """
        _OPEN_OAUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize?appid={0}&redirect_uri={1}&response_type=code&scope={2}&state={3}&component_appid={4}#wechat_redirect"
        return _OPEN_OAUTH_URL.format(app_id, urllib.quote(redirect_uri, safe=''), scope, state, c_app_id)

    @classmethod
    def openGetAccessToken(cls, app_id, code, c_app_id, token):
        """开放平台--网页授权获取code
        https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1419318590&token=&lang=zh_CN
        """
        _OPEN_TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/component/access_token?appid={0}&code={1}&grant_type=authorization_code&component_appid={2}&component_access_token={3}"
        return HttpClient().get(_OPEN_TOKEN_URL.format(app_id, code, c_app_id, token))

    @classmethod
    def openRefreshAccessToken(cls, app_id, c_app_id, c_access_token, refresh_token):
        """开放平台--网页授权获取code
        https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1419318590&token=&lang=zh_CN
        """
        _OPEN_REFRESH_URL = "https://api.weixin.qq.com/sns/oauth2/component/refresh_token?appid={0}&grant_type=refresh_token&component_appid={1}&component_access_token={2}&refresh_token={3}"
        return HttpClient().get(_OPEN_REFRESH_URL.format(app_id, c_app_id, c_access_token, refresh_token))
