#!/usr/bin/python

# Tested on python2,CentOS6
# Tool for reverse engineering.
# I can do to any kind of server, especially using Ansible, speedily and accurately analyzable.

import subprocess
import os
import sys
from datetime import datetime as dt

if len(sys.argv)!=2:
  print("Usage: outputFilePath")
  print(sys.argv)
  sys.exit(0)
COUNTFILE = sys.argv[1]
RECORDTIME = COUNTFILE + ".date"

#print("WARNING: Execute as root")
#cmd = "sudo netstat -anp | egrep 'tcp|udp|icmp'"
cmd = "netstat -anp | egrep 'tcp|udp|icmp'"

proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
result = proc.communicate()
stdout = result[0]
stdout = stdout.strip()

# Ports>=THRESPORT and not in EXCLUDE_HIGHPORTS are summerized as "HIGH", since high ports are normally a kind of ports assigned randomly for one time transmission.
THRESPORT=10000  # Dynamic Private Port Number(49152-65535) -> no. ssh uses 3xxxx.
EXCLUDE_HIGHPORTS = [""]
# ----------------------------------------------------------------------------------------------------------
# Sampl      [0]       [1]   [2] [3]                         [4]                         [5]         [6]
# ----------------------------------------------------------------------------------------------------------
# Ignored tcp        0      0 0.0.0.0:16909               0.0.0.0:*                   LISTEN      -
# Ignored tcp        0      0 0.0.0.0:16910               0.0.0.0:*                   LISTEN      -
# USE     tcp        0      0 x.x.x.x:514                 x.x.x.x:60145          ESTABLISHED -
# USE     tcp        0      0 x.x.x.x:3389                x.x.x.x:39636         TIME_WAIT   -
# USE     tcp        0      0 x.x.x.x:39190               x.x.x.x:10022          ESTABLISHED -
# USE     tcp        0      0 x.x.x.x:22                  x.x.x.x:37564         ESTABLISHED -
# ----------------------------------------------------------------------------------------------------------
# Output data format
# SourceIP:SourcePort,DestIP:DestPort,count
#

data = {}
# 0. Read Process Count file
# *Each line
#  cmd,count
if os.path.isfile(COUNTFILE):
  with open(COUNTFILE) as f:
    for line in f.readlines():
      line = line.strip()
      sps=line.split(",")
      data[",".join(sps[0:len(sps)-1])] = int(sps[len(sps)-1])

source = ""
dest = ""
proto = ""

# 1. Read and merge processes
for line in stdout.split("\n"):
  sps = line.split()
  source = sps[3]
  dest = sps[4]
  proto = sps[0]

  ## Improved for IPv6
  div=source.split(":")
  (sourceIP,sourcePort)=(":".join(div[0:len(div)-1]),div[-1])
  div=dest.split(":")
  (destIP,destPort)=(":".join(div[0:len(div)-1]),div[-1])

  if sourcePort.find("*")!=-1 or destPort.find("*")!=-1:
    continue

  if int(sourcePort)>=THRESPORT and sourcePort not in EXCLUDE_HIGHPORTS:
    source=":".join([sourceIP,"HIGH"])
  if int(destPort)>=THRESPORT and destPort not in EXCLUDE_HIGHPORTS:
    dest=":".join([destIP,"HIGH"])

  key = ",".join([proto,source,dest])
  if key not in data.keys():
    data[key]=0
  data[key] = data[key]+1

with open(COUNTFILE,"w") as f:
  for key in sorted(data.keys()):
    f.write(",".join([key,str(data[key])]))
    f.write("\n")

with open(RECORDTIME,"a") as f:
    f.write(dt.now().strftime('%Y/%m/%d %H:%M:%S'))
    f.write("\n")
