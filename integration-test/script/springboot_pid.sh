#!/bin/bash
jps | grep -E "jar" | awk '{print $1}' | tr -d '\n'