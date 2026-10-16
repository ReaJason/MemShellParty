package com.reajason.javaweb.memshell.shelltool.antsword;

import com.reajason.javaweb.memshell.config.ConfigField;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.utils.CommonUtil;
import com.reajason.javaweb.utils.StringUtils;
import lombok.*;
import lombok.experimental.SuperBuilder;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
@Getter
@SuperBuilder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class AntSwordConfig extends ShellToolConfig {
    @ConfigField
    @Builder.Default
    private String pass = CommonUtil.getRandomString(8);
    @ConfigField
    @Builder.Default
    private String headerName = "User-Agent";
    @ConfigField
    @Builder.Default
    private String headerValue = CommonUtil.getRandomString(8);

    public static abstract class AntSwordConfigBuilder<C extends AntSwordConfig, B extends AntSwordConfig.AntSwordConfigBuilder<C, B>>
            extends ShellToolConfig.ShellToolConfigBuilder<C, B> {
        public B pass(final String pass) {
            if (StringUtils.isNotBlank(pass)) {
                this.pass$value = pass;
                pass$set = true;
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
}
