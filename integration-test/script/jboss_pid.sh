#!/bin/sh

TARGET_PATTERN='Main|jboss-modules.jar'

for pid_dir in /proc/*; do
    if [ -d "$pid_dir" ] && ! [ -z "$(echo "$pid_dir" | sed 's|/proc/||' | grep -E '^[0-9]+$')" ]; then
        PID=$(echo "$pid_dir" | sed 's|/proc/||')
        CMDLINE_FILE="$pid_dir/cmdline"
        if [ -r "$CMDLINE_FILE" ]; then
            FULL_CMD=$(sed 's/\x0/ /g' "$CMDLINE_FILE")
            if [ -z "$FULL_CMD" ]; then
                continue
            fi
            if echo "$FULL_CMD" | grep -E -q "$TARGET_PATTERN"; then
                echo $PID
            fi
        fi
    fi
done