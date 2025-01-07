#!/bin/bash
ps -ef | grep Resin | grep -v grep | awk '{print $2}' | tr -d '\n'