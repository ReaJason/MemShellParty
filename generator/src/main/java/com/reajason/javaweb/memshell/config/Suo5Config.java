package com.reajason.javaweb.memshell.config;

import com.reajason.javaweb.utils.CommonUtil;
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
public class Suo5Config extends ShellToolConfig {
    @Builder.Default
    private String headerName = "User-Agent";
    @Builder.Default
    private String headerValue = CommonUtil.getRandomString(8);
}