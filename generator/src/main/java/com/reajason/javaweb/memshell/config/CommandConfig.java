package com.reajason.javaweb.memshell.config;

import com.reajason.javaweb.utils.CommonUtil;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;
import org.apache.commons.lang3.StringUtils;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
@Getter
@SuperBuilder
@ToString
public class CommandConfig extends ShellToolConfig {

    /**
     * 接收参数的请求头或请求参数名称
     */
    @Builder.Default
    private String paramName = CommonUtil.getRandomString(8);

    /**
     * 加密器
     */
    @Builder.Default
    private Encryptor encryptor = Encryptor.RAW;

    /**
     * 实现类
     */
    @Builder.Default
    private ImplementationClass implementationClass = ImplementationClass.RuntimeExec;

    /**
     * 命令执行模板，例如 sh -c "{command}" 2>&1，使用 {command} 作为占位符
     */
    private String template;

    public static abstract class CommandConfigBuilder<C extends CommandConfig, B extends CommandConfig.CommandConfigBuilder<C, B>>
            extends ShellToolConfig.ShellToolConfigBuilder<C, B> {
        public B paramName(String paramName) {
            if (StringUtils.isNotBlank(paramName)) {
                paramName$value = paramName;
                paramName$set = true;
            }
            return self();
        }
    }


    public enum ImplementationClass {
        RuntimeExec, ForkAndExec;

        public static ImplementationClass fromString(String encryptor) {
            if (encryptor != null && encryptor.equals("ForkAndExec")) {
                return ForkAndExec;
            }
            return RuntimeExec;
        }
    }

    public enum Encryptor {
        RAW, DOUBLE_BASE64;

        public static Encryptor fromString(String encryptor) {
            if (encryptor != null && encryptor.equals("DOUBLE_BASE64")) {
                return DOUBLE_BASE64;
            }
            return RAW;
        }
    }
}
