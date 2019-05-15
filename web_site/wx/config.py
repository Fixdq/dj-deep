# -*- coding: utf-8 -*-
"""
Created on 2014-5-13

@author: skycrab
"""


class WxPayConf(object):
    """配置账号信息"""
    # =======【基本信息设置】=====================================
    # 微信公众号身份的唯一标识。审核通过后，在微信发送的邮件中查看
    APPID = 'wx3694aca4adaf0c18'
    APPSECRET = 'c30f2618afa8c7fc6fec422818dfbd59'
    # 受理商ID，身份标识
    MCHID = ''
    # 商户支付密钥Key。审核通过后，在微信发送的邮件中查看
    KEY = ''

    # =======【异步通知url设置】===================================
    # 异步通知url，商户根据实际开发过程设定
    NOTIFY_URL = ''

    # =======【证书路径设置】=====================================
    # 证书路径,注意应该填写绝对路径
    SSLCERT_PATH = '/******/cacert/apiclient_cert.pem'
    SSLKEY_PATH = '/******/cacert/apiclient_key.pem'

    # =======【curl超时设置】===================================
    CURL_TIMEOUT = 30

    # =======【HTTP客户端设置】===================================
    HTTP_CLIENT = 'REQUESTS'  # ("URLLIB", "CURL", "REQUESTS")


class WxPayConf_shop(object):
    """学妹美店账号信息"""
    # =======【基本信息设置】=====================================
    # 微信公众号身份的唯一标识。审核通过后，在微信发送的邮件中查看 学妹美店
    APPID = 'wx9afaf3cae8ccb874'
    APPSECRET = '3e05251bf75baf3a0693b200d5426be8'
    # 受理商ID，身份标识
    MCHID = '1426481902'
    # 商户支付密钥Key。审核通过后，在微信发送的邮件中查看
    KEY = 'c1395afb94c542503a31b24d55cead46'

    # =======【异步通知url设置】===================================
    # 异步通知url，商户根据实际开发过程设定
    NOTIFY_URL = 'http://show.xuemei99.com/callback/wxpayback'

    # =======【证书路径设置】=====================================
    # 证书路径,注意应该填写绝对路径
    SSLCERT_PATH = '/home/django/xuemei_show/media/shop_cacert/apiclient_cert.pem'
    SSLKEY_PATH = '/home/django/xuemei_show/media/shop_cacert/apiclient_key.pem'

    # =======【curl超时设置】===================================
    CURL_TIMEOUT = 30

    # =======【HTTP客户端设置】===================================
    HTTP_CLIENT = 'REQUESTS'  # ("URLLIB", "CURL", "REQUESTS")
