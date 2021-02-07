# silver-scan
another tool gathering ports/fingers/dirs/pictures

## Install
```
apt install chromium-browser nmap masscan apache2
```
download tools from github:
```
https://github.com/maurosoria/dirsearch
https://github.com/nccgroup/scrying/releases
```
python depency
```
python3 -m pip install python-Wappalyzer
python3 -m pip install threadpool
```
config file:
```
dirsearch  $path_to_python_dirsearch.py
http2png  $path_to_bin_scrying
webpath  $path_to_webserver/scan
```
## Usage
```
start.sh $path_to_ip_file
# file format can be recognized by masscan
```
report.html will be generated at $path_to_webserver/scan.

e.g:
ip.txt
```
192.168.10.1/24
192.166.8.2-254
199.166.11.22
```
scan
```
start.sh ip.txt
```
report.html will be at /var/www/html/scan/20210207_ip/report.html after scan complete

## note
it is just a demo version, many features is on the way...
