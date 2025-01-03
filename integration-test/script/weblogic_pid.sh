#!/bin/bash
pid=""

if command -v ps &> /dev/null; then
    pid=$(ps -ef | grep weblogic | grep -v grep | awk '{print $2}')
fi

if [ -z "$pid" ]; then
    pid=$(jps 2>/dev/null | grep " Server" | awk '{print $1}')
fi

echo "$pid" | tr -d '\n'