#!/bin/bash
pgrep -f 'Resin|-Dresin' | tr -d '\n'