#!/bin/bash
ps -ef | grep "jetty.home" | grep -v grep | awk '{print $2}' | tr -d '\n'