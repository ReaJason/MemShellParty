package com.reajason.javaweb.probe.config;

import lombok.Getter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

/**
 * @author ReaJason
 * @since 2025/6/30
 */
@Getter
@SuperBuilder
@ToString
public class ResponseBodyConfig extends ProbeContentConfig {
    private String server;

    /**
     * 获取参数的请求头或请求参数名称
     */
    private String reqParamName;

    /**
     * 内置执行类加载的字节码
     */
    private String base64Bytes;
}
