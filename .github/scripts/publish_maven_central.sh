#!/usr/bin/env bash
#
# 发布到 Maven Central，并对上传阶段的瞬时失败自动重试。
#
# 背景：Sonatype 的 maven-snapshots 端点偶发地对同一次发布中的部分 PUT 返回 401，
# 同一批次其余文件（pom/jar/module 及其 .asc）照常上传，本地用同一个 token 也能通过
# 鉴权。Gradle 的 maven-publish 对上传不做重试，一次抖动就会让整个十几分钟的任务失败，
# 远程还会留下缺 sources/javadoc 的半成品快照。
#
# 重试是安全的：快照可覆盖写；发布失败时不会产生已 released 的 deployment，
# 因此整任务重跑等价于把没传完的文件补上。凭据真失效时每次都会失败，
# 首次尝试的原始日志已在构建输出里，不会被重试淹没。
#
# 用法：publish_maven_central.sh [gradle task]（默认 publishAllToMavenCentral）

set -uo pipefail

task=${1:-publishAllToMavenCentral}
attempts=${PUBLISH_ATTEMPTS:-3}
# 只重试网络与服务端的瞬时错误。400/422 是请求本身有问题、403 是命名空间权限，
# 都是确定性的，重试只会把同一个错误延迟几分钟再报一遍。
transient='Received status code (401|408|429|5[0-9][0-9])|Connection reset|Read timed out|Remote host closed|Could not write to'

for ((attempt = 1; attempt <= attempts; attempt++)); do
    log=$(mktemp)
    if ./gradlew "$task" 2>&1 | tee "$log"; then
        rm -f "$log"
        exit 0
    fi

    if ! grep -qE "$transient" "$log"; then
        echo "::error::'$task' 因非瞬时错误失败（见上方日志），不再重试"
        rm -f "$log"
        exit 1
    fi

    if ((attempt == attempts)); then
        echo "::error::'$task' 连续 $attempts 次遇到瞬时上传错误，放弃；原始错误见上方日志"
        rm -f "$log"
        exit 1
    fi

    echo "::warning::'$task' 第 $attempt/$attempts 次遇到瞬时上传错误，准备重试"
    rm -f "$log"
    # 退避后再试：抖动通常来自服务端的短暂鉴权/负载状态，立刻重试容易再撞上
    sleep $((attempt * 15))
done