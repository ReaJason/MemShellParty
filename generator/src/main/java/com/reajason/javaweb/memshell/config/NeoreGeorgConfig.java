package com.reajason.javaweb.memshell.config;

import com.reajason.javaweb.memshell.utils.CommonUtil;
import lombok.*;
import lombok.experimental.SuperBuilder;

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
}