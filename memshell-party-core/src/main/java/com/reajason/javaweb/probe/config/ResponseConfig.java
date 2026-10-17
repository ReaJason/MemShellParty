package com.reajason.javaweb.probe.config;

import com.reajason.javaweb.utils.NameSampler;
import com.reajason.javaweb.utils.StringUtils;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

/**
 * HTTP 响应回显配置，ResponseBody 与 ResponseHeader 两种探测方式共用。
 *
 * @author ReaJason
 * @since 2025/6/30
 */
@Getter
@SuperBuilder
@ToString
public class ResponseConfig extends ProbeContentConfig {
    private String server;

    /**
     * 获取参数/命令的请求头或请求参数名称
     */
    @Builder.Default
    private String reqParamName = NameSampler.sampleWord();

    /**
     * 内置执行类加载的字节码
     */
    @Setter
    private String base64Bytes;

    /**
     * 命令执行模板，使用 {command} 作为占位符
     */
    private String commandTemplate;

    /**
     * ResponseHeader 探测的回显响应头名称。
     * 留空时由生成器随机生成（X- 前缀），并写回本配置供结果展示。
     */
    @Setter
    private String respHeaderName;

    public static abstract class ResponseConfigBuilder<C extends ResponseConfig, B extends ResponseConfig.ResponseConfigBuilder<C, B>>
            extends ProbeContentConfig.ProbeContentConfigBuilder<C, B> {
        public B reqParamName(String reqParamName) {
            if (StringUtils.isNotBlank(reqParamName)) {
                reqParamName$value = reqParamName;
                reqParamName$set = true;
            }
            return self();
        }
    }
}
