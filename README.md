# silver-scan
another tool gathering ports/fingers/dirs/pictures

## Install
```
apt install chromium-browser nmap masscan
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
```
## Usage
```
start.sh $path_to_ip_file
# file format can be recognized by masscan
```
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
report location
```
http://your_ip:58080/mamasaidthenameistooshort/list
```
other usefull link
```
http://your_ip:58080/mamasaidthenameistooshort/        # history scans
http://your_ip:58080/mamasaidthenameistooshort/w       # show by waight
```

## note
it is still a demo version, many features is on the way...
