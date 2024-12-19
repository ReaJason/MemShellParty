#!/bin/bash
rm -rf ../boot/src/main/resources/static/assets/*

mkdir -p ../boot/src/main/resources/static/assets/
cp dist/vite.svg ../boot/src/main/resources/static/
cp -R dist/assets/* ../boot/src/main/resources/static/assets/

mkdir -p ../boot/src/main/resources/templates
cp dist/index.html ../boot/src/main/resources/templates/index.html