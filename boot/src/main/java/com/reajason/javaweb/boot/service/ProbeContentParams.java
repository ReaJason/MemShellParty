package com.reajason.javaweb.boot.service;

/**
 * 探测内容相关的全部可选参数。
 * <p>
 * 不同 probeMethod 只消费其中一部分字段，由 {@link ProbeContentConfigMapper} 按 probeMethod 分派。
 * {@code server} 与 {@code sleepServer} 在 REST 契约中是两个独立字段（分别供 ResponseBody 与 Sleep
 * 使用），此处保留该区分以维持行为等价；MCP 入口两者传同值。
 *
 * @author ReaJason
 */
public record ProbeContentParams(
        String host,
        int seconds,
        String server,
        String sleepServer,
        String reqParamName,
        String commandTemplate) {
}
