#!/bin/bash
pgrep -a java | awk '{print $1}' | tr -d '\n'