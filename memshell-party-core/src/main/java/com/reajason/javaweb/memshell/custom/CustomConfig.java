package com.reajason.javaweb.memshell.custom;

import com.reajason.javaweb.memshell.config.ConfigField;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
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
public class CustomConfig extends ShellToolConfig {
    @ConfigField
    private String shellClassBase64;
}
