#!/bin/bash
ps -ef | grep Bootstrap | grep -v grep | awk '{print $2}' | tr -d '\n'