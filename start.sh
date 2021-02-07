#!/bin/bash
# $1 file name contains ips
#######################

workdir=$(dirname $(readlink -f "$0"))
cd ${workdir}
webdir=$(awk '{if($1 == "webpath") print $2}' config)
webdir=${webdir:-/var/www/html/scan}
logdir="logs"

t_name=${1##*/}
filename=${t_name%_*}
#get current day
#curday=`date +%Y-%m-%d-%H%M%S`
curday=`date +%Y%m%d`
scan_log=${curday}_${filename}_scan.log
open_ports_raw=${curday}_${filename}_open.log
open_ports=${curday}_${filename}_ports.log


function log_time()
{
    time=`date '+%Y-%m-%d %H:%M:%S'`
    echo ${time}" | "${1} >> ${scan_log}
}

function check_dirs()
{
        if [ ! -d "${webdir}" ]; then
                mkdir -p ${webdir}
        fi

        if [ ! -d "${logdir}" ]; then
                mkdir -p ${logdir}
        fi
}


##################### main process ###########################

check_dirs

#scan open ports first
log_time "Start Port Scan"
masscan -iL $1 -p1-65535 --open --rate=10000 > ${open_ports_raw}
masscan -iL $1 -p1-65535 --open --rate=10000 >> ${open_ports_raw}
sort -u ${open_ports_raw} > ${open_ports_raw}_t
rm ${open_ports_raw}
mv ${open_ports_raw}_t ${open_ports_raw}
log_time "Port Scan End"

#get open ports from raw data
cat ${open_ports_raw} | sed 's/Discovered open port //g' | sed 's/tcp on //g' | awk -F"/" '{print $2":"$1}' | sed 's/[ ][ ]*//g' | sort > ${open_ports}

#detail scan
log_time "Detail Scan Start"
python3 ${workdir}/scan.py ${open_ports}

log_time "End Scan"
mv ${curday}_${filename}_* ${logdir}/
mv ${curday}_${filename} ${webdir}/

