#!/bin/bash
jps | grep -E "ASMain|GlassFishMain" | awk '{print $1}' | tr -d '\n'