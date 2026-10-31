#!/bin/bash
# 传统 WebSphere 的 startServer.sh 会同时保留 launcher（WsServerLauncher）和真正的
# server JVM（com.ibm.ws.runtime.WsServer）：两者都命中 WSLauncher，把多个 PID 拼成
# 一个进程号会让 jattach 报 "Process <拼接值> not found"。
# OpenLiberty 的 server 进程命令行是 tools/ws-server.jar。
pgrep -n -f 'com\.ibm\.ws\.runtime\.WsServer|ws-server\.jar' | tr -d '\n'
