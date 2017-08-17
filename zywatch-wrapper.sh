#!/bin/bash
if [ $# -ne 2 ];then
  echo "usage $0 [check script to update and run] [config file]"
  exit
fi
source ${2}
if [ ${UPDATE} -eq 1 ];then
  cd $(dirname ${1})
  git checkout -f ${GITBRANCH}
  git pull
fi
${1} 2> /dev/null
