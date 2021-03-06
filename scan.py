import threading, os, sys, time, getopt
import requests, re
import queue
import threadpool
import logging
import json
import socket
import ssl
import random
from lib.basic import *
from app import *
from datetime import datetime
from Wappalyzer import Wappalyzer, WebPage
import OpenSSL.crypto as crypto
from requests.adapters import HTTPAdapter
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

CONNECT_TIMEOUT = 6
MAX_REPEATED_COUNT = 50
allow_random_useragent = True
allow_random_x_forward = True

g_wappalyzer = Wappalyzer.latest()
g_scan_tag = "12345678"

# 随机HTTP头
USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/58.0.3029.96 Chrome/58.0.3029.96 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:17.0; Baiduspider-ads) Gecko/17.0 Firefox/17.0",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9b4) Gecko/2008030317 Firefox/3.0b4",
    "Mozilla/5.0 (Windows; U; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; BIDUBrowser 7.6)",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.99 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; Touch; LCJB; rv:11.0) like Gecko",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; AcooBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
    "Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.35; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
    "Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2pre) Gecko/20070215 K-Ninja/2.1.1",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9) Gecko/20080705 Firefox/3.0 Kapiko/3.0",
    "Mozilla/5.0 (X11; Linux i686; U;) Gecko/20070322 Kazehakase/0.4.5",
    "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko Fedora/1.9.0.8-1.fc10 Kazehakase/0.5.6",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
    "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52",
]


def random_useragent(condition=False):
    if condition:
        return random.choice(USER_AGENTS)
    else:
        return USER_AGENTS[0]


def random_x_forwarded_for(condition=False):
    if condition:
        return '%d.%d.%d.%d' % (
            random.randint(1, 254), random.randint(1, 254), random.randint(1, 254), random.randint(1, 254))
    else:
        return '8.8.8.8'


def set_header():
    headers = {
        'User-Agent': random_useragent(allow_random_useragent),
        'X-Forwarded-For': random_x_forwarded_for(allow_random_x_forward),
        "Accept-Language": "zh-CN,zh;q=0.8,en;q=0.6",
    }
    return headers


def init_db(word_dir):
    global g_scan_tag
    new_scan = Scans(g_scan_tag, word_dir)
    try:
        db.session.add(new_scan)
        db.session.commit()
    except Exception as e:
        logging.info("Error happened in init_db" + str(e))
        return


def save_scan(in_port_info):
    global g_scan_tag
    new_data = Assets(in_port_info, g_scan_tag)
    try:
        db.session.add(new_data)
        db.session.commit()
    except Exception as e:
        logging.info("Error happened in save_scan " + str(e) + " " + in_port_info.dump())
        return


def update_dirs_db(in_port_info):
    global g_scan_tag
    t_w = compute_weight(in_port_info)
    try:
        db.session.query(Assets).filter(Assets.ip == in_port_info.ip).filter(Assets.port == in_port_info.port).\
            filter(Assets.scan_tag == g_scan_tag).update({'weight': t_w, "dirs": in_port_info.dirs})
        db.session.commit()
    except Exception as e:
        logging.info("Error happened in save_scan " + str(e) + " " + in_port_info.dump())
        return


####
# PORT   STATE SERVICE VERSION
# 22/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
# Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
###
# get str "ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)"
##########
def get_svc_name_from_nmap(in_port_info, nmap_str):
    t_l = nmap_str.split("\n")
    t_l2 = t_l[1].split()
    in_port_info.svc_name = " ".join(t_l2[2:])


class HostInfo:
    def __init__(self, ip):
        self.ip = ip
        self.ports_info = []

    def push(self, port_info):
        self.ports_info.append(port_info)

    def del_port(self, port_info):
        self.ports_info.remove(port_info)

    def __repr__(self):
        t_info = ""
        for one_port_i in self.ports_info:
            t_info += one_port_i.dump()
        return t_info


class Http2png:
    user = ""
    bin = ""
    png_path = ""

    @staticmethod
    def init():
        global g_conf
        ret = os.popen(r"id|awk -F= '{print $2}'|awk -F\( '{print $1}'").read().strip()
        if ret == "0":
            try:
                Http2png.user = g_conf["http2png_user"]
            except:
                Http2png.user = "clt"
        else:
            Http2png.user = ""

        Http2png.bin = g_conf["http2png"]
        Http2png.png_path = g_conf["http2png_path"]

    @staticmethod
    def _extract_png_path(exec_output):
        logging.info("_extract_png_path output : " + exec_output)
        idx = exec_output.find("ReportItem")
        if idx > 0:
            t = exec_output[idx:]
            idx2 = t.find("file:")
            if idx2 > 0:
                return t[idx2:].split('"')[1]
        # parse failed
        return ""

    @staticmethod
    def url2png(in_port_info):
        url = in_port_info.get_url()
        global g_conf
        full_png_path = ""
        if "abs_png_path" not in g_conf:
            full_png_path = os.popen("cd " + Http2png.png_path + "; pwd").read().strip()
            logging.info("set png base path: " + full_png_path)
            g_conf["abs_png_path"] = full_png_path
        else:
            full_png_path = g_conf["abs_png_path"]
        cmd = "cd " + full_png_path + "; " + Http2png.bin + " -s -o ./ -t " + url
        if Http2png.user != "":
            cmd = "su - " + Http2png.user + " -c " + "'" + cmd + "'" # url can not have '
        logging.info("cmd in url2png : " + cmd)
        ret = os.popen(cmd).read()
        in_port_info.png = Http2png._extract_png_path(ret)
        logging.info("get png path in url2png: " + in_port_info.png)


class NmapSvc:
    que = queue.Queue()
    svc_stop = False

    @staticmethod
    def consumer():
        logging.info("NmapSvc consumer start ")
        while not NmapSvc.svc_stop:
            try:
                p_info = NmapSvc.que.get(timeout=5)
                nmap_ret = ""

                print("Nmap start scan " + p_info.ip + ":" + p_info.port)
                logging.info("Nmap start scan " + p_info.ip + ":" + p_info.port)
                cmd = "nmap -sC -sV -p" + p_info.port + " -n -Pn " + p_info.ip + " 2>/dev/null"
                ret = os.popen(cmd).read()
                idx = ret.find("PORT ")
                if idx > -1:
                    idx2 = ret.find("Service detection performed")
                    if idx2 > idx:
                        nmap_ret = ret[idx:idx2-1]
                    else:
                        nmap_ret = ret[idx:]
                else:
                    nmap_ret = ret

                p_info.nmap = nmap_ret
                get_svc_name_from_nmap(p_info, nmap_ret)
                save_scan(p_info)
            except Exception as e:
                logging.info("nmap svc " + str(e))
                # queue will raise exception, if queue is empty and timeout
        logging.info("NmapSvc consumer exit ")

    @staticmethod
    def put(in_port_info):
        NmapSvc.que.put(in_port_info)
        logging.info("put in NmapSvc " + str(in_port_info) + " , que size: " + str(NmapSvc.que.qsize()))

    @staticmethod
    def stop():
        NmapSvc.svc_stop = True

    @staticmethod
    def wait_for_empty():
        logging.info("wait for empty in NmapSvc start")
        while not NmapSvc.que.empty():
            time.sleep(5.0)
        logging.info("wait for empty in NmapSvc end")


class DirBrute:
    que = queue.Queue()
    svc_stop = False

    @staticmethod
    def consumer():
        global g_conf
        script_ds = g_conf["dirsearch"]

        logging.info("dirbrute consumer start ")
        while not DirBrute.svc_stop:
            try:
                p_info = DirBrute.que.get(timeout=5)
                url = p_info.get_url()
                print("start dirsearch " + url)
                logging.info("start dirsearch " + url)
                t_f = p_info.ip + "_" + p_info.port + "_" + "ds.txt"
                logging.info("python3 " + script_ds + " -u " + url + " -w $(dirname " + script_ds + ")/db/dicc.txt -F -e \* --plain-text-report=" + t_f)
                os.system("python3 " + script_ds + " -u " + url + " -w $(dirname " + script_ds + ")/db/dicc.txt -F -e \* --timeout=4 --plain-text-report=" + t_f + " >/dev/null")
                p_info.dirs = parse_dirsearch(t_f)
                #os.system("rm -f " + t_f)
                update_dirs_db(p_info)
            except Exception as e:
                # queue will raise exception(nothing in exception info), if queue is empty and timeout
                logging.info("Exception in DirBrute, " + str(e)) #############
        logging.info("dirbrute consumer exit ")

    @staticmethod
    def put(in_port_info):
        DirBrute.que.put(in_port_info)
        logging.info("put in DirBrute " + str(in_port_info) + " , que size: " + str(DirBrute.que.qsize()))

    @staticmethod
    def stop():
        DirBrute.svc_stop = True

    @staticmethod
    def wait_for_empty():
        logging.info("wait for empty in DirBrute start")
        while not DirBrute.que.empty():
            time.sleep(5.0)
        logging.info("wait for empty in DirBrute end")


def find_repeated_size(in_file):
    global MAX_REPEATED_COUNT
    repeated_size_list = []

    cmd = "awk '{print $2}' " + in_file + " | sort -n | uniq -c |sort -rn -k 1"
    t_l = os.popen(cmd).read().split('\n')[:-1]
    for one_line in t_l:
        t_list = one_line.strip().split()
        if safe_int(t_list[0]) > MAX_REPEATED_COUNT:
            repeated_size_list.append(t_list[1])
    #print("repeated_size_list" + str(repeated_size_list))
    return repeated_size_list


def check_one_dir(one_dir_line):
    dirsearch_line = re.compile('^\d{3}\s+\d+\w\s+http.*$')
    if dirsearch_line.match(one_dir_line):
        return True
    else:
        return False


def parse_dirsearch(file):
    ret_str = ""
    t_list = []
    try:
        repeated_size_list = find_repeated_size(file)
        with open(file) as f_h:
            for line in f_h:
                if not check_one_dir(line):
                    continue
                l_l = line.strip().replace("MB", "000KB").replace("KB","000B").split()
                if l_l[1] in repeated_size_list:
                    continue
                t_url = l_l[2]
                url_pr = urlparse(l_l[2])
                l_l.append(t_url)
                l_l[2] = url_pr.path
                t_list.append(l_l)

        t_list2 = sorted(t_list, key=lambda x:(safe_int(x[0]), -safe_int(x[1][:-1]), x[2]))
        for one_l in t_list2:
            link = '<a href="' + one_l[3].replace("\"", "%22") + '" target="_blank">' + one_l[2] + '</a><br>'
            line = one_l[0] + " " + one_l[1].rjust(8, " ") + " " + link + "\n"
            ret_str += line

        if len(repeated_size_list) > 0:
            ret_str += ','.join(repeated_size_list) + " size repeat over " + str(MAX_REPEATED_COUNT) + " times , deleted"
    except Exception as e:
        ret_str = "open " + file + " failed in parse_dirsearch " + str(e) ##########
        logging.info("open " + file + " failed in parse_dirsearch " + str(e))

    if ret_str == "":
        ret_str = "no 200 or 401 page found"
    return ret_str


# s_type: "http[s]"
def send_http(in_port_info, s_type):
    in_port_info.svc_name = s_type
    url = in_port_info.get_url()
    try:
        r = requests.get(url, timeout=CONNECT_TIMEOUT, allow_redirects=True, verify=False)
        return True
    except Exception as e:
        in_port_info.svc_name = ""
        return False


def try_http(in_port_info):
    if not send_http(in_port_info, "https"):
        return send_http(in_port_info, "http")
    else:
        return True


def get_cert(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        s.connect((host, int(port)))
        # upgrade the socket to SSL without checking the certificate
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
        # get certificate
        cert_bin = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
        t_cert = x509.get_subject().CN
        if not t_cert:
            t_cert = ""
        return t_cert
    except Exception as e:
        logging.info("in get_cert " + str(e) + " " + host + ":" + str(port))
        return ""


def check_banner(in_port_info):
    global g_finger_conf
    headers = ""

    finger_i = in_port_info.finger
    if in_port_info.svc_name == "https":
        finger_i.cert_info = get_cert(in_port_info.ip, int(in_port_info.port))
    url = in_port_info.get_url()

    try:
        s = requests.Session()
        s.keep_alive = False
        s.mount(url, HTTPAdapter(max_retries=2))
        response = requests.get(url, stream=False, headers=set_header(), timeout=CONNECT_TIMEOUT, allow_redirects=False, verify=False)
        html = response.content
        headers = response.headers
        finger_i.ret_code = response.status_code
        finger_i.content_len = len(html) if 'Content-Length' not in headers else safe_int(headers['Content-Length'])
        finger_i.server = '' if 'Server' not in headers else headers['Server']
        if html:
            try:
                titlestr = re.search(r'<title>(.*?)</title>', html, flags=re.I | re.M)
                if titlestr:
                    finger_i.title = titlestr.group(1)
                if not finger_i.title:
                    finger_i.title = ""
            except Exception as e:
                finger_i.title = ""
            # self defined cms banner check
            for mark_info in g_finger_conf:
                mark_info = mark_info.strip('\n').split('|')
                if mark_info[1] == 'header':
                    try:
                        if re.search(mark_info[3], headers[mark_info[2]], re.I):
                            finger_i.cms = mark_info[0]
                    except Exception as e:
                        continue
                elif mark_info[1] == 'file':
                    try:
                        if mark_info[2] != '/':
                            t_url = url + mark_info[2]
                            t_resp = requests.get(t_url, stream=False, headers=set_header(), timeout=CONNECT_TIMEOUT, allow_redirects=False, verify=False)
                            html = t_resp.content
                        if re.search(mark_info[3], html, re.I):
                            finger_i.cms = mark_info[0]
                    except Exception as e:
                        continue
                elif mark_info[1] == 'ico':
                    try:
                        ico = url + mark_info[2]
                        icoresp = requests.get(ico, stream=False, headers=set_header(), timeout=CONNECT_TIMEOUT, allow_redirects=False, verify=False)
                        ico_Length = 0 if 'Content-Length' not in icoresp.headers else icoresp.headers['Content-Length']
                        if ico_Length == mark_info[3]:
                            finger_i.cms = mark_info[0]
                    except Exception as e:
                        continue

        if response.status_code in [301, 302]:
            finger_i.title = "Location To:" + headers['Location']
    except Exception as e:
        logging.info("Exception in check_banner " + str(in_port_info) + "\t" + str(e))


def get_finger(in_port_info):
    global g_wappalyzer
    try:
        webpage = WebPage.new_from_url(in_port_info.get_url(), verify=False, timeout=6)
        ret = g_wappalyzer.analyze_with_versions_and_categories(webpage)
    except Exception as e:
        logging.info("Exception in get_finger, " + str(e))
        ret = []
 
    t_finger = ""
    for one_key in ret:
        if len(ret[one_key]["versions"]) != 0:
            t_finger += one_key + " " + ret[one_key]["versions"][0] + "\n"
        else:
            t_finger += one_key + "\n"
            #in_port_info.finger = json.dumps(ret, sort_keys=True, indent=4)

    in_port_info.finger.wappalyzer_info = t_finger
    check_banner(in_port_info)
    logging.info(in_port_info.finger)


# key process
def check_services(in_host_info):
    port_count = len(in_host_info.ports_info)
    for one_p_info in in_host_info.ports_info:
        if port_count >= 100:  # 端口开启过多的异常资产降低权重
            one_p_info.weight_factor = -10000
        if try_http(one_p_info):
            get_finger(one_p_info)
            Http2png.url2png(one_p_info)
            save_scan(one_p_info)  # save first so we can get partial results, update it after dirbrute
            if port_count < 100:
                DirBrute.put(one_p_info)
            #one_p_info.wait_for_dirs()
        else:
            NmapSvc.put(one_p_info)


def pre_init(ports_file):
    # set work directory
    work_dir = "static"
    idx = ports_file.find("_ports")
    if idx != -1:
        work_dir += "/" + ports_file[:idx]
    else:
        dt = datetime.now()
        work_dir += "/" + dt.strftime('%Y%m%d-%H%M%S')
    os.mkdir(work_dir)
    os.chdir(work_dir)

    # insert scan task id into database
    init_db(work_dir)

    # set path to save pngs
    os.mkdir(g_conf["http2png_path"])

    # set user account to exec scrying tool
    if g_conf["http2png_user"] not in os.popen("grep -E '/bin/bash|/bin/sh' /etc/passwd|awk -F: '{print $1}'").read().strip().split("\n"):
        t_pass = random.choice('abcdefghijklmnopqrstuvwxyz!@#$%^&*()')
        os.system("useradd " + g_conf["http2png_user"] + " -p " + t_pass)
    os.system("chown " + g_conf["http2png_user"] + ": " + g_conf["http2png_path"])


class CltScan:
    def __init__(self, in_ip_ports_file):
        self.f = in_ip_ports_file
        self.l = {}
        self.hosts = []

    def test_dump(self):
        for one in self.hosts:
            print(one)

    def _sort_list(self):
        for one_ip_list in self.l.values():
            one_ip_list.sort()

    def _generate_hosts(self):
        rabbish_l = []
        for tmp in self.l.items():
            t_host = HostInfo(tmp[0])
            for one_port in tmp[1]:
                t_host.push(PortInfo(tmp[0], one_port))
            if len(tmp[1]) < 100:
                self.hosts.append(t_host)
            else:  # 当某个ip对应的端口数超过100时，该资产多半有异常，比如 waf 蜜罐 之类，会耗费大量扫描时间
                rabbish_l.append(t_host)
        self.hosts.extend(rabbish_l)   # 异常资产放到最后

    def init(self):
        Http2png.init()

        with open(self.f) as f_h:
            for line in f_h:
                t_l = line.strip().split(":")
                ip = t_l[0]
                port = t_l[1]
                if ip not in self.l:
                    self.l[ip] = []
                self.l[ip].append(port)
        self._sort_list()
        self._generate_hosts()

    def start_services(self):
        global g_conf

        t_dirbrute = threading.Thread(target=DirBrute.consumer)
        t_dirbrute.start()

        t_nmap = threading.Thread(target=NmapSvc.consumer)
        t_nmap.start()

        thread_count = int(g_conf["work_thread_cnt"])
        print("thread count: " + str(thread_count))
        pool = threadpool.ThreadPool(thread_count)
        reqs = threadpool.makeRequests(check_services, self.hosts)
        [pool.putRequest(req) for req in reqs]
        pool.wait()
        pool.dismissWorkers(thread_count, do_join=True)

        DirBrute.wait_for_empty()
        DirBrute.stop()
        NmapSvc.wait_for_empty()
        NmapSvc.stop()
        t_dirbrute.join()
        t_nmap.join()
        print("end for scan ")
        #self.test_dump()

    def generate_report(self):
        global g_conf
        report_pre = """<!DOCTYPE html>
<html>
	<head>
		<title>Clt Scan Report</title>
		<style>
			#main {
				width: 60%;
				margin: 0 auto;
			}
			.section {
				width: 100%;
				display: block;
				clear: both;
				border-top: 1px solid;
			}
			.imagebox {
				width: 300px;
				float: left;
				margin: 2px;
				border-style: dotted;
				border-width: 2px;
				border-color: LightGray;
			}
		</style>
	</head>
	<body>
		<div id="main">"""
        report_end = """		</div>
	</body>
</html>"""

        html_body = ""
        for one_host in self.hosts:
            html_body += "<h3>" + one_host.ip + "</h3>"
            for one_port in one_host.ports_info:
                html_body += "<h4>&nbsp;&nbsp;" + one_port.port + "</h4>"
                if one_port.svc_name.find("http") >= 0:
                    png_relative_path = g_conf["http2png_path"] + "/" + one_port.png
                    html_body += '<a href="' + one_port.get_url().replace('"','%22') + '"><div class="imagebox"><img width="400px" src="' + \
                        png_relative_path + '" /><br>' + one_port.get_url() + '</div></a>'

                    html_body += '<div class="section"><h5>&nbsp;&nbsp;&nbsp;&nbsp;finger print</h5>'
                    finger = str(one_port.finger)
                    html_body += '<p style="font-size: 12px">' + finger.replace("\n", "<br>").replace(" ","&nbsp;") + '</p></div>'

                    html_body += '<div class="section"><h5>&nbsp;&nbsp;&nbsp;&nbsp;diretories</h5>'
                    html_body += '<p style="font-size: 12px">' + one_port.dirs.replace("\n", "<br>") + '</p></div>'
                else:
                    html_body += '<div class="section"><h5>&nbsp;&nbsp;&nbsp;&nbsp;nmap results</h5>'
                    html_body += '<p style="font-size: 12px">' + one_port.nmap.replace("\n", "<br>").replace(" ","&nbsp;") + '</p></div>'
            html_body += "<br>"

        html_all = report_pre + html_body + report_end
        #print("report ---------: \n" + html_all) #################
        with open("report.html", 'w') as f_h:
            f_h.write(html_all)

    def iter_list(self):
        for tmp in self.l.items():
            print("==== process ip: " + tmp[0])
            for one_port in tmp[1]:
                print(one_port)


if __name__ == '__main__':
    parse_conf("./config")
    logging.basicConfig(filename=g_conf["log_name"], level=logging.INFO,
                        format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s', datefmt='%Y-%m-%d')
    g_scan_tag = int(time.time())
    myscan = CltScan(sys.argv[1])
    myscan.init()
    pre_init(sys.argv[1])
    myscan.start_services()
    myscan.generate_report()

