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

## note
it is just a demo version, many features is on the way...
