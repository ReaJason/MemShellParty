package com.reajason.javaweb.memshell.config;

import com.reajason.javaweb.utils.CommonUtil;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.apache.commons.lang3.StringUtils;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
@Getter
@SuperBuilder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class GodzillaConfig extends ShellToolConfig {
    @Builder.Default
    private String pass = CommonUtil.getRandomString(8);
    @Builder.Default
    private String key = CommonUtil.getRandomString(8);
    @Builder.Default
    private String headerName = "User-Agent";
    @Builder.Default
    private String headerValue = CommonUtil.getRandomString(8);

    public static abstract class GodzillaConfigBuilder<C extends GodzillaConfig, B extends GodzillaConfigBuilder<C, B>>
            extends ShellToolConfig.ShellToolConfigBuilder<C, B> {
        public B pass(String pass) {
            if (StringUtils.isNotBlank(pass)) {
                this.pass(pass);
            }
            return self();
        }

        public B key(String key) {
            if (StringUtils.isNotBlank(key)) {
                this.key(key);
            }
            return self();
        }

        public B headerName(String headerName) {
            if (StringUtils.isNotBlank(headerName)) {
                this.headerName(headerName);
            }
            return self();
        }

        public B headerValue(String headerValue) {
            if (StringUtils.isNotBlank(headerValue)) {
                this.headerValue(headerValue);
            }
            return self();
        }
    }
}