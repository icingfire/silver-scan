#!/bin/bash
# $1 file name contains ips
#######################

workdir=$(dirname $(readlink -f "$0"))
cd ${workdir}
logdir="logs"

t_name=${1##*/}
t_name2=${t_name%_*}
filename=${t_name2%.*}
#filename=${${${1##*/}%_*}%.*}
#get current day
curday=`date +%Y%m%d-%H%M%S`
scan_log=${curday}_${filename}_scan.log
open_ports_raw=${curday}_${filename}_open.log
open_ports=${curday}_${filename}_ports.log
scan_again="y"

function log_time()
{
  time=`date '+%Y-%m-%d %H:%M:%S'`
  echo ${time}" | "${1} >> ${scan_log}
}

function check_dirs()
{
  if [ ! -d "${logdir}" ]; then
    mkdir -p ${logdir}
  fi
}

function check_db_init_stat()
{
  if [ ! -f 'm.db' ]; then
    python3 -c 'from app import *;db.create_all()'
  fi
}

function start_web()
{
  pid=$(ps -eo pid,cmd|grep app.py|grep -v grep|grep "$(which python3)"|awk '{print $1}')
  [ -n "${pid}" ] && kill "${pid}"
  nohup python3 app.py >> scan.log 2>&1 &
}

##################### main process ###########################

check_dirs
check_db_init_stat

if [ ! -f "$1" ]; then
  echo "file $1 not found, exit"
  exit
fi

#scan open ports first
log_time "Start Port Scan"
masscan -iL $1 -p1-65535 --open --rate=5000 > ${open_ports_raw}
if [ ${scan_again} == "y" ]; then
  masscan -iL $1 -p1-65535 --open --rate=5000 > ${open_ports_raw}2
  sed 's/Discovered open port //g' ${open_ports_raw} | sed 's/tcp on //g' | awk -F"/" '{print $2":"$1}' | sed 's/[ ][ ]*//g' | sort -u > ${open_ports}_t
  sed 's/Discovered open port //g' ${open_ports_raw}2 | sed 's/tcp on //g' | awk -F"/" '{print $2":"$1}' | sed 's/[ ][ ]*//g' | sort -u > ${open_ports}2_t
  diff ${open_ports}_t ${open_ports}2_t > ${open_ports}_diff   # get diff to see whether worth a second masscan
  cat ${open_ports}2_t >> ${open_ports}_t
  sort -u ${open_ports}_t > ${open_ports}
  rm ${open_ports_raw} ${open_ports_raw}2 ${open_ports}2_t ${open_ports}_t
else
  sed 's/Discovered open port //g' ${open_ports_raw} | sed 's/tcp on //g' | awk -F"/" '{print $2":"$1}' | sed 's/[ ][ ]*//g' | sort -u > ${open_ports}
fi
log_time "Port Scan End"

#detail scan
log_time "Details Scan Start"
start_web
python3 ${workdir}/scan.py ${open_ports}

log_time "End Scan"
mv ${curday}_${filename}_* ${logdir}/
#mv ${curday}_${filename} ${webdir}/

