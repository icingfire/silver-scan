import time
import re

g_conf = {}
g_finger_conf = []


def safe_int(in_str):
    p = re.compile(r'^(\d+)')
    m_o = p.match(in_str)
    if m_o:
        return int(m_o.group(1))
    else:
        return -1


def parse_conf(config_file):
    global g_conf, g_finger_conf
    try:
        finger_conf_flag = 0
        with open(config_file) as f_h:
            for line in f_h:
                if line.find("#####") > -1:
                    finger_conf_flag = 1
                    continue
                if finger_conf_flag == 0:
                    t_l = line.strip(' \r\n').split(" ")
                    g_conf[t_l[0]] = " ".join(t_l[1:]).strip(' ')
                else:
                    g_finger_conf.append(line.strip())
    except Exception as e:
        print("read " + config_file + " failed." + str(e))


class FingerInfo:
    def __init__(self):
        self.wappalyzer_info = ""
        self.content_len = 0
        self.ret_code = 500
        self.cert_info = ""
        self.title = ""
        self.cms = ""
        self.server = ""

    def __repr__(self):
        return self.wappalyzer_info + "\n" + str(self.ret_code) + "\t" + \
            str(self.content_len) + "\t" + self.title + "\t" + self.cms + "\t" + self.cert_info + "\t" + self.server


class PortInfo:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.svc_name = ""
        self.png = ""
        self.dirs = "Wait for scanning"
        self.nmap = ""
        # 某些资产需要降低权重（比如某ip开启了1000个端口，很可能存在异常）
        self.weight_factor = 0
        self.finger = FingerInfo()

    def get_url(self):
        if self.svc_name == "http" and self.port == "80":
            return self.svc_name + "://" + self.ip
        elif self.svc_name == "https" and self.port == "443":
            return self.svc_name + "://" + self.ip
        return self.svc_name + "://" + self.ip + ":" + self.port

    def wait_for_nmap(self, timeout=600):
        sleep_gap = 3
        max_cnt = timeout / sleep_gap + 1
        cnt = 0
        while self.nmap == "":
            time.sleep(3.0)
            cnt += 1
            if cnt >= max_cnt:
                #logging.info("wait time out in nmap scan " + self.ip + ":" + self.port)
                break

    def wait_for_dirs(self, timeout=60):
        sleep_gap = 3
        max_cnt = timeout / sleep_gap + 1
        cnt = 0
        while self.dirs == "":
            time.sleep(3.0)
            cnt += 1
            if cnt >= max_cnt:
                #logging.info("wait time out in dirs bruting " + self.get_url())
                break

    def __repr__(self):
        return self.ip + " " + self.port + " " + self.svc_name

    def dump(self):
        return self.ip + " " + self.port + " " + self.svc_name + "\n" + \
            "png path: " + self.png + "\n" + \
            "dirs: " + self.dirs + "\n" + \
            "nmap result: " + self.nmap + "\n" + \
            "finger print: " + str(self.finger) + "\n"

if __name__ == '__main__':
    print(safe_int("300B"))
    print(safe_int("200MB"))
    print(safe_int("100K"))
    print(safe_int("aaa400B"))
    print(safe_int("600Bcccc300"))
    print(safe_int(""))