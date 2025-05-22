#!/bin/bash
pgrep -f 'ASMain|GlassFishMain' | tr -d '\n'