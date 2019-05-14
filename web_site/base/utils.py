# -*- coding: utf-8 -*-
__author__ = 'whos'

from datetime import datetime
from django.utils import timezone
import time
import random
import hashlib


def time_string(time_):
    if time_ is None:
        return ''
    try:
        return time_.strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        return ''


def date_string(time_):
    if time_ is None:
        return ''
    try:
        return time_.strftime('%Y-%m-%d')
    except ValueError:
        return ''


def string_time(string, formatstring):
    if string is None:
        return ''
    try:
        return datetime.strptime(string, formatstring)
    except ValueError:
        return ''


def get_current_time(time_zone):
    # 获取settings中的时区
    current_tz = timezone.get_current_timezone()
    # 按照该时区格式化UTC时间
    local_time = current_tz.normalize(time_zone)
    return local_time


def timestamp_to_time(timestamp):
    """时间戳转换为时间"""
    return time.strftime('%Y-%m-%d %H-%M-%S',time.localtime(timestamp))


def get_current_time_string(time_zone):
    return time_string(get_current_time(time_zone))


def minutes_hours_days(minutes):
    if minutes < 60:
        return str(minutes)+'分钟'
    hours = minutes/60
    if hours > 24 and hours % 24 == 0:
        return str(hours/24)+'天'
    return str(hours)+'小时'


def transforms_int(string_a, default=None):
    """把string转换为int"""
    if string_a is None:
        return default

    try:
        return int(str(string_a).strip())
    except ValueError:
        return default


def transforms_float(string_a, default=None):
    """把string转换为float"""
    if string_a is None:
        return default

    try:
        return float(str(string_a).strip())
    except ValueError:
        return default


def float_to_int(float_num, default=None):
    """float to int"""
    if float_num is None:
        return default
    else:
        try:
            return int(float_num)
        except ValueError:
            return default


def check_string_none(string_a):
    """把string转换为float"""
    if string_a is None:
        return None

    str_a = string_a.strip()
    if len(str_a) > 0:
        return str_a
    else:
        return None


def choice_desc(choiceType, choiceTuple):
    """从元组中查找指定类型的描述"""
    for choice in choiceTuple:
        if choice[0] == choiceType:
            return choice[1]
    return ''


def gen_id(number):
    """生成唯一的用户ID"""
    return str(random.SystemRandom().randint(10**(number-1), 10**number-1))


def gen_id_number(number):
    """生成唯一的用户ID"""
    return random.SystemRandom().randint(10**(number-1), 10**number-1)


def gen_oid(first_char):
    """根据用户ID生成订单ID"""
    return first_char+str(int(time.time()*1000))+gen_id(6)


random_list = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
               'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
               'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
               'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
               'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']


def gen_hlskey(number):
    """生成hls的key"""
    return ''.join(random.sample(random_list, number))


def md5(string):
    m = hashlib.md5()
    m.update(string)
    return m.hexdigest()


def generate_signature(data, key):
    data_list = sorted(data.iteritems(), key=lambda data:data[0])
    sign_string = ''
    for result in data_list:
        sign_string += result[0]+'='+str(result[1])+'&'
    sign_string += key
    return md5(sign_string)


def signature_valid(data, key):
    sign = data['signature']
    data.pop('signature')
    timestamp = transforms_int(data['timestamp'])
    time_now = int(time.time())
    if timestamp < time_now - 10 or timestamp > time_now:
        return False, str(time_now)
    signed = generate_signature(data, key)
    if sign == signed:
        return True, signed
    return False, signed
