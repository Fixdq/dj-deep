# -*- coding: utf-8 -*-
"""
Created on 2014-5-14
django 帮助函数

@author: skycrab

@sns_userinfo
def oauth(request):
    openid = request.openid

"""
import json
import logging
import base64
from functools import wraps
from django.conf import settings
from django.core.cache import cache
from django.shortcuts import redirect, render_to_response
from django.contrib.auth import login, logout, authenticate
from rest_framework.authtoken.models import Token
from core.redis_number import RedisStat
from django.core.urlresolvers import reverse

from .common import CommonHelper
from wx import class_property, WeixinHelper
from datetime import timedelta
from django.utils import timezone
from shop.models import ShopInfo
from account.models import User
import urllib, urlparse
import time

logger = logging.getLogger('control')


class Helper(CommonHelper):
    """微信具体逻辑帮组类"""

    @class_property
    def cache(cls):
        """返回cache对象"""
        return cache

    @class_property
    def secret_key(cls):
        """返回cookie加密秘钥"""
        return settings.SECRET_KEY


def sns_userinfo_proxy_callback(callback=None):
    """
    网页授权获取用户信息装饰器
    callback(openid, userinfo):
        return user
    """
    def wrap(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            if 'MicroMessenger' in request.META.get('HTTP_USER_AGENT', ''):
                shop = request.GET.get('shop', None)
                if not shop:
                    response = func(request, *args, **kwargs)
                else:
                    # 判断支付情况

                    if request.is_secure():
                        url = request.build_absolute_uri().replace('https://', 'http://')
                        return redirect(url)
                    unionid = request.session.get('unionid', '')
                    timestamp_now = int(time.time())
                    ok, unionid = Helper.check_cookie(unionid)

                    redis = RedisStat()
                    if ok:
                        # 判断微信用户token是否存在，如果不存在，则需要授权
                        redis_info = redis.get(unionid)
                        if not redis_info:
                            ok = False
                        else:
                            ws = json.loads(redis_info)
                            if not ws['unionid']:
                                ok = False

                    if not ok:
                        # unionid出错，重新授权
                        state = request.GET.get('state', None)
                        if state:
                            # aa|bb|cc  aa:最近一级上级推客 bb:谁转发过来 cc:时间戳
                            state_list = urllib.unquote(state).split('|')
                            if len(state_list) != 3:
                                state = '0|0|%d' % timestamp_now
                        else:
                            state = '0|0|%d' % timestamp_now

                        state += '|%s' % shop

                        rs_id = redis.get('redirect_url_id')
                        if rs_id:
                            url_id = redis.incr('redirect_url_id')
                        else:
                            url_id = 1
                            redis.set('redirect_url_id', url_id)
                        redis.set_ttl('redirect_url_id_%d' % url_id, request.build_absolute_uri(), 60)

                        # 跳转到代理微信认证服务器
                        redirect_url = 'http://%s.control.binli360.com%s' % (shop, reverse('open:proxy_callback'))
                        scope = 'snsapi_base'
                        state = 'base|%s|%s' % (state, url_id)
                        url = WeixinHelper.proxy(redirect_url, scope, state, 'mobile')
                        return redirect(url)
                    else:

                        # 获取绑定的User对象
                        user = authenticate(unionid=unionid)
                        if user:
                            # token, goc = Token.objects.get_or_create(user=user)
                            login(request, user)
                            response = func(request, *args, **kwargs)
                            # response.set_cookie(shop+'_key', token.key, path='/')
                            response.set_cookie(shop, unionid, path='/')
                        else:
                            response = func(request, *args, **kwargs)
            else:
                response = func(request, *args, **kwargs)
            return response
        return inner
    return wrap

sns_userinfo = sns_userinfo_proxy_callback()


def sns_userinfo_proxy_test_callback(callback=None):
    """
    网页授权获取用户信息装饰器
    callback(openid, userinfo):
        return user
    """
    def wrap(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            if 'MicroMessenger' in request.META.get('HTTP_USER_AGENT', ''):
                # logger.debug('sns_userinfo_proxy_test_callback is wechat')
                shop = request.GET.get('shop', None)
                if not shop:
                    response = func(request, *args, **kwargs)
                else:
                    # 判断支付情况

                    if request.is_secure():
                        url = request.build_absolute_uri().replace('https://', 'http://')
                        return redirect(url)
                    unionid = request.session.get('unionid', '')
                    timestamp_now = int(time.time())
                    ok, unionid = Helper.check_cookie(unionid)
                    # logger.debug('sns_userinfo_proxy_test_callback sessino unionid is : %s' % unionid)

                    redis = RedisStat()
                    if ok:
                        # 判断微信用户token是否存在，如果不存在，则需要授权
                        redis_info = redis.get(unionid)
                        if not redis_info:
                            ok = False
                        else:
                            ws = json.loads(redis_info)
                            if not ws['unionid']:
                                ok = False

                    if not ok:
                        # unionid出错，重新授权
                        state = request.GET.get('state', None)
                        if state:
                            # aa|bb|cc  aa:最近一级上级推客 bb:谁转发过来 cc:时间戳
                            state_list = urllib.unquote(state).split('|')
                            if len(state_list) != 3:
                                state = '0|0|%d' % timestamp_now
                        else:
                            state = '0|0|%d' % timestamp_now

                        state += '|%s' % shop

                        rs_id = redis.get('redirect_url_id')
                        if rs_id:
                            url_id = redis.incr('redirect_url_id')
                        else:
                            url_id = 1
                            redis.set('redirect_url_id', url_id)
                        redis.set_ttl('redirect_url_id_%d' % url_id, request.build_absolute_uri(), 60)

                        # 跳转到代理微信认证服务器
                        redirect_url = 'http://%s.control.binli360.com%s' % (shop, reverse('open:proxy_callback_test'))
                        scope = 'snsapi_base'
                        state = 'base|%s|%s' % (state, url_id)
                        url = WeixinHelper.proxy(redirect_url, scope, state, 'mobile')
                        # logger.debug('sns_userinfo_proxy_test_callback redirect_url is %s' % url)
                        return redirect(url)
                    else:
                        # logger.debug('sns_userinfo_proxy_test_callback unionid is : %s' % unionid)
                        pass
                        # 获取绑定的User对象
                        user = authenticate(unionid=unionid)
                        if user:
                            # token, goc = Token.objects.get_or_create(user=user)
                            login(request, user)
                            response = func(request, *args, **kwargs)
                            # response.set_cookie(shop+'_key', token.key, path='/')
                            response.set_cookie(shop, unionid, path='/')
                        else:
                            response = func(request, *args, **kwargs)
            else:
                response = func(request, *args, **kwargs)
            return response
        return inner
    return wrap

sns_userinfo_test = sns_userinfo_proxy_test_callback()
