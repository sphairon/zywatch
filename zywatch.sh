#!/bin/bash
############################################################################
#                                                                          #
# Test script to check DSL CPE's                                           #
# Currently this tests are supported:                                      #
# * IPv4 WAN connectivity                                                  #
# * IPv6 WAN connectivity                                                  #
# * DNS resolving                                                          #
# * up to two DynDNS domains are up to date                                #
# * DUT GUI is accessible and responds within a given time                 #
# * SIP accounts are registered                                            #
# * Software version of DUT is up-to-date                                  #
# * overall system satus is of DUT is OK (no failed services               #
# * check script version is up-to-date                                     #
#                                                                          #
# This program is free software: you can redistribute it and/or modify     #
# it under the terms of the GNU Affero General Public License as           #
# published by the Free Software Foundation, either version 3 of the       #
# License, or (at your option) any later version.                          #
#                                                                          #
# This program is distributed in the hope that it will be useful,          #
# but WITHOUT ANY WARRANTY; without even the implied warranty of           #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            #
# GNU Affero General Public License for more details.                      #
#                                                                          #
# You should have received a copy of the GNU Affero General Public License #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.    #
#                                                                          #
# Usage:                                                                   #
#                                                                          #
# cd /usr/local/source/                                                    #
# git clone https://github.com/steglicd/zywatch.git                        #
# cd zywatch                                                               #
# ./zywatch.sh setup                                                       #
# editor /etc/zy.conf                                                      #
# update at least:                                                         #
# * DUTUSER                                                                #
# * DUTPASS                                                                #
# * DYNDNS1                                                                #
# * DYNDNS2                                                                #
# * MONITORINGPASSWD                                                       #
# * DIAL (if modem is connected)                                           #
#                                                                          #
# afterwards the script will run once every 10 minutes and report          #
# DSL CPE status to a monitoring server                                    #
#                                                                          #
# All the used variables are defined in zy.conf                            #
#                                                                          #
############################################################################

CURRENTVERSION=3.0
CONFIGFILE="/etc/zy.conf"
SCRIPTNAME=$0
LOCKFILE="/var/lock/$(basename ${0}).lock"
DEPENDENCIES="nsca-client dnsutils curl ppp git"
IP="0.0.0.0"
IP6="::0"
GUIACCESS=0

# helper function to read configuration
doReadConfig()
{
  . ${CONFIGFILE}
  [ -z $V6 ] && V6=1
  HOSTNAME=$MONITORINGHOST
  [ -z $LANIF ] && LANIF="eth0"
  [ -z $HOSTNAME ] && HOSTNAME=$(cat /etc/hostname)
  [ -z $KEEPLOG ] && KEEPLOG=0
}

# cleanup function
doExit()
{
  rm ${LOCKFILE}
  exit
}

# print results to HDMI
doOut()
{
  if [ ${HDMIOUT} -eq 1 ];then
    if [ ${1} -eq 1 ];then
      shift
      echo -e "\e[31m ${@} \e[0m" > /dev/console
      echo "${@}"
    else
      shift
      echo -e "\e[32m ${@} \e[0m" > /dev/console
      echo "${@}"
    fi
  fi
  echo ${@} >> ${LOGFILE}
}

# send test result to monitoring server
doSend()
{
  echo "password=${MONITORINGPASSWD}" > /etc/send_nsca.cfg
  echo "encryption_method=3" >> /etc/send_nsca.cfg
  echo "${HOSTNAME},${1},${2},${3}"| /usr/sbin/send_nsca -H ${MONITORINGTARGET} -p 5667 -d , -c /etc/send_nsca.cfg > /dev/null 2>&1
}

# helper function to setup environment after the git clone
doSetup()
{
  local cronjob="/etc/cron.d/zyxel"
  local link="/usr/local/bin/$(basename ${SCRIPTNAME})"
  [ -z $ZYPATH ] && ZYPATH=$(pwd)

  # install dependencies
  apt-get update
  apt-get install -y ${DEPENDENCIES}

  # prepare cronjob
  echo "@reboot root ${ZYPATH}/${SCRIPTNAME} > /dev/null" > ${cronjob}
  echo "*/10 * * * * root ${ZYPATH}/zywatch-wrapper.sh ${ZYPATH}/${SCRIPTNAME} ${CONFIGFILE} > /dev/null 2>&1" >> ${cronjob}

  # place config file
  [ ! -f ${CONFIGFILE} ] && cp ./zy.conf ${CONFIGFILE}
  echo "ZYPATH=${ZYPATH}" >> ${CONFIGFILE}
  echo "please review ${CONFIGFILE}"

  # create a link so user can invoke the script manually
  ln -s ${ZYPATH}/$(basename ${SCRIPTNAME}) ${link}
  sync
}

# helper function to login to GUI
doLogin()
{
  local cookie="/tmp/cookies.txt"
  rm ${cookie} 2> /dev/null

  # login, grab start page, count seconds until startup page is delivered
  LOGIN=$(curl -s -i http://${DEFAULT}/webng.cgi -c $cookie)
  local sessionid=$(cat ${cookie} |grep SESSION_ID |awk '{print $7}')
  local start=$(date +%s)
  LOGIN=$(curl -b ${cookie} -s -i -d "tid=&sid=${sessionid}&controller=SasLogin&action=login&id=0&LoginName=${DUTUSER}&LoginPass=${DUTPASS}" http://${DEFAULT}/webng.cgi)
  local fin=$(date +%s)
  local logintime=$((${fin} - ${start}))

  local login_ok=$(echo "${LOGIN}"|grep SYSTEM |cut -d \> -f 6 |cut -d \< -f 1)
  if [ -z ${login_ok} ];then
    doOut 1 "GUI login FAILED with username ${DUTUSER}"
    doSend "${MON_GUIACCESS}" 2 "GUI login FAILED with username ${DUTUSER}"
    GUIACCESS=0
    return
  else
    GUIACCESS=1
  fi

  # logout
  curl -b ${cookie} -s -i -d "tid=&sid=${sessionid}&controller=SasLogin&action=logout" http://${DEFAULT}/webng.cgi > /dev/null
  if [ ${logintime} -gt 30 ];then
      doSend "${MON_GUIACCESS}" 2 "CRITICAL: GUI response in ${logintime} seconds |timer=${logintime};10;30;0;120"
      return
  fi
  if [ ${logintime} -gt 20 ];then
      doSend "${MON_GUIACCESS}" 1 "WARNING: GUI response in ${logintime} seconds |timer=${logintime};10;30;0;120"
      return
  fi
  doSend "${MON_GUIACCESS}" 0 "OK: GUI response in ${logintime} seconds |timer=${logintime};10;30;0;120"
}

# helper function to make a outgoing analogue call
doCall()
{
  sleep $[ ( ${RANDOM} % 600 )  + 1 ]s
  START=$(date +%s)
  /usr/sbin/chat -r /tmp/report -v ABORT   BUSY \
  ABORT   'NO DIALTONE' \
  ABORT   'NO CARRIER' \
  REPORT  CONNECT \
  TIMEOUT 60 \
  '' ATZ \
  OK 'ATH' \
  OK 'AT&F' \
  OK 'AT+FCLASS=0' \
  OK 'AT+MS=B103' \
  OK 'AT s37=3' \
  OK ATDT${DIAL} \
  CONNECT 'ATH'  > ${MODEM} < ${MODEM}
  FINISH=$(date +%s)
}

# test if outgoing calls are working
doTelephony()
{
  local reportfile="/tmp/report"
  if [ ! -c ${MODEM} ];then
    doOut 0 "no modem connected"
    doSend "${MON_CALL}" 0 "No modem connected|duration=0;0;0;0;0 retry=0;0;0;0;0"
    return
  fi

  rm ${reportfile} 2> /dev/null
  doCall
  local result=$(cat ${reportfile} |grep CONNECT)
  counter=0
  while [ "${result}" = "" -a ${counter} -lt ${DIALRETRY} ];do
    sleep $(echo ${RANDOM} | cut -b 1-2)
    rm ${reportfile} 2> /dev/null
    doCall
    result=$(cat ${reportfile} |grep CONNECT)
    counter=$((counter + 1))
  done
  if [ "$result" != "" ];then
    local duration=$((${FINISH} - ${START}))
    if [ ${duration} -lt ${DIALWARNDURATION} ];then
      doOut 0 "Telephony call is OK"
      doSend "${MON_CALL}" 0 "Telephony call is OK|duration=${duration};${DIALWARNDURATION};${DIALMAXDURATION};0;60 retry=${counter};1;2;0;3"
      return
    fi
    if [ ${duration} -lt ${DIALMAXDURATION} ];then
      doOut 0 "Telephony call is WARNING (call establishment took ${duration} seconds)"
      doSend "${MON_CALL}" 1 "Telephony call is WARNING (call establishment took ${duration} seconds)|duration=${duration};${DIALWARNDURATION};${DIALMAXDURATION};0;60 retry=${counter};1;2;0;3"
      return
    fi
    doOut 0 "Telephony call is CRITICAL (call establishment took ${duration} seconds)"
    doSend "${MON_CALL}" 2 "Telephony call is CRITICAL (call establishment took ${duration} seconds)|duration=${duration};${DIALWARNDURATION};${DIALMAXDURATION};0;60 retry=${counter};1;2;0;3"
  else
    doOut 1 "failed to do a phone call"
    doSend "${MON_CALL}" 2 "Telephony call is failed|duration=0;${DIALWARNDURATION};${DIALMAXDURATION};0;60 retry=${counter};1;2;3"
  fi
}

# test if DNS is working
doDNS()
{
  nslookup ${DNSTEST} > /dev/null 2>&1

  if [ $? -eq 0 ];then
    doOut 0 "DNS Service is OK"
    doSend "${MON_DNS}" 0 "DNS is OK"
  else
    doOut 1 "DNS Service Failed"
    doSend "${MON_DNS}" 2 "DNS is Failed"
  fi
}

# test if IPv6 connectivity is working
doTestV6()
{
  if [ $V6 -eq 0 ];then
    doSend "${MON_IPV6DEFAULT}" 0 "No IPv6 used"
    doSend "${MON_IPV6WANIP}" 0 "No IPv6 used"
    doSend "${MON_IPV6LANIP}" 0 "No IPv6 used"
    return
  fi

  local default6=$(ip -6 route |grep default)
  if [ "${default6}" != "" ];then
    doOut 0 "IPv6 Route OK"
    doSend "${MON_IPV6DEFAULT}" 0 "IPv6 Route is OK"
  else
    doOut 1 "IPv6 Route FAILED"
    doSend "${MON_IPV6DEFAULT}" 2 "No IPv6 default Route"
  fi

  local wgetoutfile="/tmp/wget"
  rm ${wgetoutfile} 2> /dev/null

  wget -6 -T ${WGETTIMEOUT} --tries=${WGETRETRY} ${WGETMISC} -O ${wgetoutfile} ${IPURL}
  IP6=$(cat ${wgetoutfile})

  if [ "${IP6}" != "" ];then
    doOut 0 "WAN IPv6: ${IP6}"
    doSend "${MON_IPV6WANIP}" 0 "WAN IP is ${IP6}"
  else
    doOut 1 "Failed to get WAN IPv6"
    doSend "${MON_IPV6WANIP}" 2 "Failed to get WAN IPv6 from ${IPURL}"
  fi

  local lan=$(ip addr |grep inet6 |grep global |awk '{print $2}' |grep -v ^fde2)
  if [ "${lan}" != "" ];then
    doOut 0 "LAN IPv6: ${lan}"
    doSend "${MON_IPV6LANIP}" 0 "LAN IP is ${lan}"
  else
    doOut 1 "Failed to get LAN IPv6"
    doSend "${MON_IPV6LANIP}" 2 "Failed to get LAN IP"
  fi
}

# test if IPv4 connectivity is working
doIPv4()
{
  local default4=$(ip route |grep default |awk '{print $3}')
  if [ "${default4}" != "" ];then
    doOut 0 "IPv4 Route OK"
    doSend "${MON_IPV4DEFAULT}" 0 "IPv4 Route is OK"
  else
    doOut 1 "IPv4 Route FAILED"
    doSend "${MON_IPV4DEFAULT}" 2 "No IPv4 default Route"
  fi
  local wgetoutfile="/tmp/wget"
  rm ${wgetoutfile} 2> /dev/null

  wget -4 -T ${WGETTIMEOUT} --tries=${WGETRETRY} ${WGETMISC} -O ${wgetoutfile} ${IPURL}
  IP=$(cat ${wgetoutfile})

  if [ "${IP}" != "" ];then
    doOut 0 "WAN IPv4: ${IP}"
    doSend "${MON_IPV4WANIP}" 0 "WAN IP is ${IP}"
  else
    doOut 1 "Failed to get WAN IPv4"
    doSend "${MON_IPV4WANIP}" 2 "Failed to get WAN IPv4"
  fi

  local lan=$(ip addr |grep inet |grep ${LANIF} |awk '{print $2}')
  if [ "${lan}" != "" ];then
    doOut 0 "LAN IPv4: ${lan}"
    doSend "${MON_IPV4LANIP}" 0 "LAN IP is ${lan}"
  else
    doOut 1 "Failed to get LAN IPv4"
    doSend "${MON_IPV4LANIP}" 2 "Failed to get LAN IP"
  fi
}

# check DynDNS accounts
doDynDNS()
{
  if [ ! -z ${DYNDNS1} ];then
    local dnsip=$(nslookup ${DYNDNS1} |grep Address |awk 'NR==2{print $2}')
    if [ "${dnsip}" = "${IP}" ];then
      doOut 0 "DynDNS Account 1 works as expected"
      doSend "${MON_DYNDNS1}" 0 "${dnsip} matches ${DYNDNS1}"
    else
      doOut 1 "DynDNS Account 1 FAILED"
      doSend "${MON_DYNDNS1}" 2 "${dnsip} does not matches ${DYNDNS1} (${IP})"
    fi
  else
    doSend "${MON_DYNDNS1}" 0 "No Account configured"
  fi

  if [ ! -z ${DYNDNS2} ];then
    local dnsip1=$(nslookup ${DYNDNS2} |grep Address |awk 'NR==2{print $2}')
    if [ "${dnsip1}" = "${IP}" ];then
      doOut 0 "DynDNS Account 2 works as expected"
      doSend "${MON_DYNDNS2}" 0 "${dnsip1} matches ${DYNDNS2}"
    else
      doOut 1 "DynDNS Account 2 FAILED"
      doSend "${MON_DYNDNS2}" 2 "${dnsip1} does not matches ${DYNDNS2}  (${IP})"
    fi
  else
    doSend "${MON_DYNDNS2}" 0 "No Account configured"
  fi
}

# check if SIP accounts are registered
doVoIP()
{
  if [ ${USEVOIP} -eq 0 ];then
    doSend "${MON_SIPACC}" 0 "No SIP Accounts used"
  fi
  local telstatus=$(echo "${LOGIN}"|grep icon_phone_ok |cut -d , -f 2)
  if [ ${telstatus} -eq 1 ];then
    doOut 0 "Telephony Status is OK"
    doSend "${MON_SIPACC}" 0 "SIP Accounts are registered"
  else
    doOut 1 "Telephony Status is FAILED"
    doSend "${MON_SIPACC}" 2 "SIP Accounts are NOT registered"
  fi
}

# check Software version and if overall system status is OK
doSystem()
{
  local systemstatus=$(echo "${LOGIN}"|grep cStatusOk |grep System)
  local software=$(echo "${LOGIN}"|grep SW |grep -i version | awk '{print $15}' |cut -d \" -f 2)
  doSend "${MON_SWVER}" 0 "${software}"
  if [ "$systemstatus" = "" ];then
    doOut 1 "System Status is FAILED"
    doSend "${MON_SYSSTAT}" 2 "Some failed services"
  else
    doOut 0 "System Status is OK"
    doSend "${MON_SYSSTAT}" 0 "No failed services"
  fi
}

# script already running?
if [ -f ${LOCKFILE} ];then
  exit
else
  touch ${LOCKFILE}
fi

# first setup
if [ "${1}" = "setup" ]; then
  doSetup
  doExit
fi

doReadConfig

[ $KEEPLOG -eq 0 ] && rm ${LOGFILE} 2> /dev/null

# find the DUT
DEFAULT=$(ip route |grep default |grep default |awk '{print $3}')
LANIF=$(ip route |grep default |grep default |awk '{print $5}')
if [ -z "${DEFAULT}" ];then
  echo " can't find DUT"
  doExit
fi

#reset and wake the console
echo -ne "\033[9;0]" > /dev/console
echo -e \\033c > /dev/console

# report check script version
doSend "${MON_MONVER}" 0 "${CURRENTVERSION}"

# start testing the DUT
doDNS
doTestV6
doIPv4
doLogin
[ $GUIACCESS -eq 1 ] && doSystem
[ $GUIACCESS -eq 1 ] && doVoIP
doDynDNS
doTelephony
doExit
