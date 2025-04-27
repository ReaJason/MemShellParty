#!/bin/bash
pgrep -f 'Main|jboss-modules.jar' | tr -d '\n'