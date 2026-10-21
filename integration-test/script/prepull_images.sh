#!/usr/bin/env bash
# 后台并行预拉某 middleware 集成测试用到的 docker 镜像，让镜像下载与 gradle 编译重叠。
# 用法: prepull_images.sh <测试源码相对目录，如 memshell/jetty> [类名 glob，如 'WebSphere*']
set -u

SRC_DIR="$1"
CLASS_GLOB="${2:-*}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_ROOT="$ROOT/integration-test/src/test/java/com/reajason/javaweb/integration"

# 镜像声明形态：.imageName("tomcat:9-jre9") / .jetty("jetty:11.0-jre17") 等带 tag 的字符串字面量
images=$(find "$TEST_ROOT/$SRC_DIR" -name "${CLASS_GLOB}.java" -print0 2>/dev/null \
  | xargs -0 grep -hoE '"[a-z0-9][a-z0-9./_-]*:[a-z0-9][a-z0-9._-]*"' 2>/dev/null \
  | tr -d '"' \
  | grep -vE ':/' \
  | sort -u)

# NeoreGeorg 测试的 python 容器（几乎每个 middleware 都会构建）
images="$images
python:3.12-slim"

echo "pre-pulling images for $SRC_DIR ($CLASS_GLOB):"
echo "$images" | grep -vE '^\s*$'

echo "$images" | grep -vE '^\s*$' | xargs -P 6 -I{} sh -c 'docker pull "{}" >/dev/null 2>&1 && echo "pulled {}" || echo "pull failed {}"'
echo "pre-pull done for $SRC_DIR"
