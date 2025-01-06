#!/bin/bash
ps -ef | grep -E 'Main|jboss-modules.jar' | grep -v grep | awk '{print $2}' | tr -d '\n'