package com.reajason.javaweb.probe.config;

import com.reajason.javaweb.utils.CommonUtil;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;
import org.apache.commons.lang3.StringUtils;

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
    @Builder.Default
    private String reqParamName = CommonUtil.getRandomString(8);

    /**
     * 内置执行类加载的字节码
     */
    private String base64Bytes;

    /**
     * 命令执行模板，使用 {command} 作为占位符
     */
    private String commandTemplate;

    public static abstract class ResponseBodyConfigBuilder<C extends ResponseBodyConfig, B extends ResponseBodyConfig.ResponseBodyConfigBuilder<C, B>>
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
