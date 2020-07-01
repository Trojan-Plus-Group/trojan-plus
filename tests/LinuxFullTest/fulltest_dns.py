'''
 This file is part of the Trojan Plus project.
 Trojan is an unidentifiable mechanism that helps you bypass GFW.
 Trojan Plus is derived from original trojan project and writing
 for more experimental features.
 Copyright (C) 2020 The Trojan Plus Group Authors.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://gnu.org/licenses/>.
'''
import dns.resolver
import traceback
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from fulltest_utils import print_time_log

RESOLVER_TIMEOUT = 3
PARALLEL_REQUEST_COUNT = 3
MAX_RETRY_COUNT = 3

query_port = 53
print_log = False

ipv4_valid_regex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

direct_lookup_domains = [
    'tmall.com',
    'qq.com',
    'baidu.com',
    'sohu.com',
    'login.tmall.com',
    'taobao.com',
    '360.cn',
    'jd.com',
    'pages.tmall.com',
    'sina.com.cn',
    'weibo.com',
    'xinhuanet.com',
    'csdn.net',
    'alipay.com',
    'zhanqi.tv',
    'panda.tv',
    'google.com.hk',
    'tianya.cn',
    'china.com.cn',
    'babytree.com',
    'sogou.com',
    'huanqiu.com',
    'yy.com',
    '17ok.com',
    'detail.tmall.com',
]

proxy_lookup_domains = [
    'mama.cn',
    'jrj.com.cn',
    'google.cn',
    '1688.com',
    'bilibili.com',
    'so.com',
    'yao.tmall.com',
    'soso.com',
    'gome.com.cn',
    'cnblogs.com',
    '6.cn',
    'hao123.com',
    'zhihu.com',
    'rednet.cn',
    '163.com',
    '3c.tmall.com',
    'aliyun.com',
    'iqiyi.com',
    'eastday.com',
    'uniqlo.tmall.com',
    'google.com',
    'nvzhuang.tmall.com',
    'subject.tmall.com',
    'food.tmall.com',
    'jianshu.com',
]


direct_lookup_non_domains = [
    '34234tmall.com',
    'qq.co564m',
    'baid545645664u.com',
    '456.co45645m',
    'login.456tmall.com',
    'tao46546bao.com',
    '360.4564cn',
    'jd.com',
    'pages.564tmall.com',
    'sina456456.45645com.cn',
    'weibo4645.com',
    'xinhua456456net.com',
    'csdn.n4645et',
    'alip46546ay.com',
    'zhanq456456i.tv',
    'pa46564nda.tv',
    'google46546.com.hk',
    'tiany76jhgfa.cn',
    'chin54353a.com.cn',
    'babytre345345e.com',
    'sogo645645wefsdfu.com',
    'huadfgffg5645645nqiu.com',
    'yy.com45645fgddf',
    '17ok.comdgdfg',
    'detail.tmall.cogd242m',
]

proxy_lookup_non_domains = [
    'mamidjod23a.cn',
    'jrj.codfsdm.cdfdn',
    'googldfse.csdfn',
    '168sdf8.csdfsom',
    'bilibdgfdgdili.cdgfdgom',
    'sdgfdgo.cofdgfdm',
    'yadgfo.tmaldgdl.cogdfgm',
    'sdgfoso.codgfdgm',
    'godgfdfgme.cdgfgom.cdgfdgn',
    'cnbldfgogs.co232m',
    '6.c342n',
    'ha243o123.co2342m',
    'zhi23424hu.c243om',
    'red243net.c5667n',
    '166453.co78m',
    '368c.tm463all.c756om',
    'ali4353yun.co876m',
    'iqiyixyi.c675om',
    'easrvutday.cohm',
    'uniqdflo.tmadsdll.cfsdom',
    'google.c1123om',
    'nvzhua123ng.tma342ll.c43om',
    'subje234ct.tma234ll.234com',
    'foo2342d.tma234ll.co2342m',
    'jian243shu.co2342m',
]


def lookup_domains(domain, ns, count, non_domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ns]
    resolver.port = query_port
    resolver.timeout = RESOLVER_TIMEOUT
    resolver.lifetime = RESOLVER_TIMEOUT

    for _ in range(0, count):
        for r in range(1, MAX_RETRY_COUNT + 1):
            try:
                answers = resolver.query(domain, 'A')
                for ip in answers:
                    ip = str(ip)
                    if not ip or not re.match(ipv4_valid_regex, ip):
                        print_time_log('failed while looking for ' +
                                       domain + ' return: ' + ip)

                if not non_domain:
                    if len(answers) < 0:
                        return False

                break

            except:
                if not non_domain:
                    if r >= MAX_RETRY_COUNT:
                        print_time_log('failed while looking for ' + domain)
                        traceback.print_exc(file=sys.stdout)
                        return False
                else:
                    break

    return True


def main_process(executor, domains, ns, count, non_domain=False):
    tasks = []
    for domain in domains:
        tasks.append(executor.submit(lookup_domains,
                                     domain, ns, count, non_domain))

    for result in as_completed(tasks):
        if not result.result():
            return False

    return True


def start_query(ns, count, port):
    global query_port
    query_port = port

    with ThreadPoolExecutor(max_workers=PARALLEL_REQUEST_COUNT) as executor:
        for _ in range(0, 2):
            print_time_log('start lookup ' +
                           str(len(direct_lookup_domains)) + ' direct domains...')
            if not main_process(executor, direct_lookup_domains, ns, count):
                return False

            print_time_log('done')

            print_time_log('start lookup ' +
                           str(len(proxy_lookup_domains)) + ' proxy domains...')
            if not main_process(executor, proxy_lookup_domains, ns, count):
                return False

            print_time_log('done')

            print_time_log('start lookup ' +
                           str(len(proxy_lookup_domains)) + ' direct NON-domains...')
            if not main_process(executor, direct_lookup_non_domains, ns, count, True):
                return False

            print_time_log('done')

            print_time_log('start lookup ' +
                           str(len(proxy_lookup_domains)) + ' proxy NON-domains...')
            if not main_process(executor, proxy_lookup_non_domains, ns, count, True):
                return False

            print_time_log('done')

    return True


if __name__ == "__main__":
    # print_log = True
    start_query("114.114.114.114", 1)
