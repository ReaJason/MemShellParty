package com.reajason.javaweb.memshell.shelltool.suo5v2;

import com.reajason.javaweb.memshell.config.ConfigField;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.utils.CommonUtil;
import com.reajason.javaweb.utils.StringUtils;
import lombok.*;
import lombok.experimental.SuperBuilder;

/**
 * @author ReaJason
 * @since 2025/2/12
 */
@Getter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class Suo5v2Config extends ShellToolConfig {
    @ConfigField
    @Builder.Default
    private String headerName = "User-Agent";
    @ConfigField
    @Builder.Default
    private String headerValue = CommonUtil.getRandomString(8);

    public static abstract class Suo5v2ConfigBuilder<C extends Suo5v2Config, B extends Suo5v2Config.Suo5v2ConfigBuilder<C, B>>
            extends ShellToolConfig.ShellToolConfigBuilder<C, B> {
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
}
