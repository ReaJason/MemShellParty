package com.reajason.javaweb.config;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
@Getter
@SuperBuilder
@ToString
public class CommandShellConfig extends ShellConfig {
    @Builder.Default
    private String headerName = "cmd";
}
