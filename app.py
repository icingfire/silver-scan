from flask import Flask, request, redirect, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from datetime import datetime
from urllib.parse import *
import re, os, platform, base64
from lib.basic import *
import cgi, time


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///m.db'
db = SQLAlchemy(app)

g_base_path = "/mamasaidthenameistooshort/"

# defines for file upload
g_upload_path = "upfiles"
if platform.system() == "Windows":
    slash = '\\'
elif platform.system() == "Linux":
    slash = '/'


def check_ip(ipAddr):
    compile_ip=re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if compile_ip.match(ipAddr):
        return True
    else:
        return False


def check_domain(domain):
    compile_dm = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$')
    if compile_dm.match(domain):
        return True
    else:
        return False


def assets_cmp(at1, at2):
    return at1.svc_name == at2.svc_name and \
        at1.dirs == at2.dirs and \
        at1.nmap == at2.nmap and \
        at1.content_len == at2.content_len and \
        at1.cert_info == at2.cert_info and \
        at1.title == at2.title and \
        at1.server == at2.server and \
        at1.cms == at2.cms


# it is a temp function for optimise old weight data in database
def re_weight_sub(in_assert):
    weight = 0
    if in_assert.status_code == 200:
        weight += 10 * in_assert.content_len
    elif in_assert.status_code == 401:
        weight += 1000
    else:
        weight += int(in_assert.content_len / 10)

    if in_assert.dirs != "":
        t_l = in_assert.dirs.split("\n")
        t_len = len(t_l)
        for i in range(5):
            if i >= t_len:
                break
            t_c = t_l[i].split()
            if len(t_c) >= 2:
                if t_c[0] == "200":
                    weight += safe_int(t_c[1])

    t_port = int(in_assert.port)
    if t_port in [22,3306,6379,8161,27017,5984,11211,2049,9200,5601,9990,5900,5901,837,50070,2181,2375,8888,389,888]:
        weight += 500

    # 非web端口优先级高于垃圾web端口
    if in_assert.svc_name != "http" and in_assert.svc_name != "https":
        weight += 100

    return weight


# it is a temp function for optimise old weight data in database
@app.route(g_base_path + "reweight", methods = ['GET'])
def re_weight():
    db_assets = Assets.query.all()
    for one_asset in db_assets:
        t_weight = re_weight_sub(one_asset)
        db.session.query(Assets).filter(Assets.id == one_asset.id).update({'weight': t_weight })
    db.session.commit()
    return "Modify all weight Done!"


def compute_weight(in_port_info):
    weight = in_port_info.weight_factor
    if in_port_info.finger.ret_code == 200:
        weight += 10 * in_port_info.finger.content_len
    elif in_port_info.finger.ret_code == 302:
        weight += 1100
    elif in_port_info.finger.ret_code == 401:
        weight += 1000
    else:
        weight += int(in_port_info.finger.content_len / 10)

    if in_port_info.dirs != "":
        t_l = in_port_info.dirs.split("\n")
        t_len = len(t_l)
        for i in range(5):
            if i >= t_len:
                break
            if t_l[i].strip() == "":  # last value
                break
            t_c = t_l[i].split()
            if t_c[0] == "200":
                weight += safe_int(t_c[1])

    t_port = int(in_port_info.port)
    if t_port in [22,3306,6379,8161,27017,5984,11211,2049,9200,5601,9990,5900,5901,837,50070,2181,2375,8888,389,888]:
        weight += 500

    # 非web端口优先级高于垃圾web端口
    if in_port_info.svc_name != "http" and in_port_info.svc_name != "https":
        weight += 100

    return weight


class Scans(db.Model):
    scan_tag = db.Column(db.Integer, primary_key=True)
    work_dir = db.Column(db.String(512), default="")

    def __init__(self, scan_tag, work_dir):
        self.scan_tag = scan_tag
        self.work_dir = work_dir


class Assets(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(256), nullable=False)
    port = db.Column(db.String(32), nullable=False)
    svc_name = db.Column(db.String(512), default="")
    png_path = db.Column(db.String(512), default="")
    dirs = db.Column(db.String(10240), default="")
    nmap = db.Column(db.String(10240), default="")
    wappalyzer = db.Column(db.String(4096), default="")
    status_code = db.Column(db.Integer, default=500)
    content_len = db.Column(db.Integer, default=0)
    cert_info = db.Column(db.String(512), default="")
    title = db.Column(db.String(512), default="")
    cms = db.Column(db.String(512), default="")
    server = db.Column(db.String(512), default="")
    scan_tag = db.Column(db.Integer)            # 每一次扫描都生成一个独立的标识
    weight = db.Column(db.Integer, default=0)   # 资产权重
    date_created = db.Column(db.DATETIME, default=datetime.utcnow())

    def __init__(self, in_port_info, scan_tag):
        self.ip = in_port_info.ip
        self.port = in_port_info.port
        self.scan_tag = scan_tag
        self.svc_name = in_port_info.svc_name
        self.png_path = in_port_info.png
        self.dirs = in_port_info.dirs
        self.nmap = cgi.escape(in_port_info.nmap).replace("\n", "<br>")
        self.wappalyzer = in_port_info.finger.wappalyzer_info
        self.status_code = in_port_info.finger.ret_code
        self.content_len = in_port_info.finger.content_len
        self.cert_info = in_port_info.finger.cert_info
        self.title = in_port_info.finger.title
        self.cms = in_port_info.finger.cms
        self.server = in_port_info.finger.server
        self.weight = compute_weight(in_port_info)


@app.route(g_base_path, methods = ['GET', 'POST'])
def scan_history():
    if request.method == 'GET':
        tags = db.session.query(Scans.scan_tag).order_by(Scans.scan_tag).all()
        scan_cnt = len(tags)
        time_l = []
        tag_l = []
        for one_t in tags:
            tag_l.append(one_t[0])
            time_l.append(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(one_t[0])))
        return render_template("history.html", count=scan_cnt, times=time_l, scan_tags=tag_l)
    elif request.method=='POST':
        t_str = []
        for one in request.form.values():
            t_str.append(one)
        return redirect(url_for("compare", id_old=t_str[-2], id_new=t_str[-1]))
    else:
        return "Unsupport Request Method"
    #return render_template("history.html", times=time_l)


def _show_scan_result_by_tag(tag):
    png_path = ""
    db_assets = []
    if tag:
        db_scan = Scans.query.filter(Scans.scan_tag == tag).all()
        if db_scan:
            png_path = db_scan[0].work_dir.replace("static/", "") + "/" + g_conf['http2png_path']
            db_assets = Assets.query.filter(Assets.scan_tag == tag)

    ip_map = {}
    for one in db_assets:
        if one.ip in ip_map:
            ip_map[one.ip].append(one)
        else:
            ip_map[one.ip] = []
            ip_map[one.ip].append(one)
    list_sort = []
    for one in ip_map.values():
        list_sort.append(sorted(one, key=lambda x:int(x.port)))
    return render_template("index.html", png_path=png_path, Assets=list_sort)


def _show_result_by_tag_weight(tag):
    png_path = ""
    db_assets = []
    if tag:
        db_scan = Scans.query.filter(Scans.scan_tag == tag).all()
        if db_scan:
            png_path = db_scan[0].work_dir.replace("static/", "") + "/" + g_conf['http2png_path']
            db_assets = Assets.query.filter(Assets.scan_tag == tag).order_by(Assets.weight.desc())
    return render_template("weight.html", png_path=png_path, Assets=db_assets)


@app.route(g_base_path + "list", methods = ['GET'])
def list():
    if request.method == 'GET':
        scan_tag = db.session.query(func.max(Scans.scan_tag)).one()
        return _show_scan_result_by_tag(scan_tag[0])
    else:
        return "Unsupport Method"


@app.route(g_base_path + "list/<tag_id>", methods = ['GET'])
def list_by_tag(tag_id):
    return _show_scan_result_by_tag(tag_id)


@app.route(g_base_path + "w", methods = ['GET'])
def list_by_weight():
    scan_tag = db.session.query(func.max(Scans.scan_tag)).one()
    return _show_result_by_tag_weight(scan_tag[0])


@app.route(g_base_path + "w/<tag_id>", methods = ['GET'])
def list_by_weight_tag(tag_id):
    return _show_result_by_tag_weight(tag_id)


@app.route(g_base_path + "filter/<id>", methods = ['GET'])
def filter_by_id(id):
    target = Assets.query.filter(Assets.id == id).one()
    orig_tag = target.scan_tag
    db.session.query(Assets).filter(Assets.content_len == target.content_len) \
        .filter(Assets.svc_name == target.svc_name) \
        .filter(Assets.dirs == target.dirs) \
        .filter(Assets.nmap == target.nmap) \
        .filter(Assets.cert_info == target.cert_info) \
        .filter(Assets.title == target.title) \
        .filter(Assets.server == target.server) \
        .filter(Assets.cms == target.cms) \
        .filter(Assets.scan_tag == target.scan_tag).update({'scan_tag': Assets.scan_tag - 200000000 })
    db.session.commit()
    return redirect(url_for('list_by_tag', tag_id=orig_tag))


@app.route(g_base_path + "compare/<id_old>/<id_new>", methods = ['GET'])
def compare(id_old, id_new):
    old_map = {}
    diff_list = []
    for one in Assets.query.filter(Assets.scan_tag == id_old):
        old_map[one.ip+":"+one.port] = one
    for new_one in Assets.query.filter(Assets.scan_tag == id_new):
        t_key = new_one.ip+":"+new_one.port
        if t_key in old_map.keys():
            if not assets_cmp(new_one, old_map[t_key]):
                diff_list.append(new_one)
        else:
            diff_list.append(new_one)

    png_path = ""
    db_scan = Scans.query.filter(Scans.scan_tag == id_new).all()
    if db_scan:
        png_path = db_scan[0].work_dir.replace("static/", "") + "/" + g_conf['http2png_path']

    ip_map = {}
    for one in diff_list:
        if one.ip in ip_map:
            ip_map[one.ip].append(one)
        else:
            ip_map[one.ip] = []
            ip_map[one.ip].append(one)
    list_sort = []
    for one in ip_map.values():
        list_sort.append(sorted(one, key=lambda x: int(x.port)))
    return render_template("index.html", png_path=png_path, Assets=list_sort)



if __name__ == '__main__':
    parse_conf("./config")
    app.run(debug=True, host="0.0.0.0", port=58080)

