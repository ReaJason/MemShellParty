#!/bin/bash
ps -ef | grep WSLauncher | grep -v grep | awk '{print $2}' | tr -d '\n'