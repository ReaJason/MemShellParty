package com.reajason.javaweb.boot.vo;

import com.reajason.javaweb.memshell.config.CommandConfig;
import lombok.Data;

import java.util.List;

/**
 * @author ReaJason
 * @since 2025/5/25
 */
@Data
public class CommandConfigVO {
    private List<CommandConfig.Encryptor> encryptors;
    private List<CommandConfig.ImplementationClass> implementationClasses;
}
