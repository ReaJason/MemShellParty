package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.memshell.packer.Packer;
import lombok.Data;

/**
 * @author ReaJason
 * @since 2024/12/18
 */
@Data
public class GenerateRequest {
    private ShellConfig shellConfig;
    private ShellToolConfigDTO shellToolConfig;
    private InjectorConfig injectorConfig;
    private Packer.INSTANCE packer;

    @Data
    static class ShellToolConfigDTO {
        private String shellClassName;
        private String godzillaPass;
        private String godzillaKey;
        private String godzillaHeaderName;
        private String godzillaHeaderValue;
        private String commandParamName;
    }

    public ShellToolConfig parseShellToolConfig() {
        if (shellConfig.getShellTool().equals(ShellTool.Godzilla)) {
            return GodzillaConfig.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .pass(shellToolConfig.getGodzillaPass())
                    .key(shellToolConfig.getGodzillaKey())
                    .headerName(shellToolConfig.getGodzillaHeaderName())
                    .headerValue(shellToolConfig.getGodzillaHeaderValue())
                    .build();
        }
        if (shellConfig.getShellTool().equals(ShellTool.Command)) {
            return CommandConfig.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .paramName(shellToolConfig.getCommandParamName())
                    .build();
        }
        throw new UnsupportedOperationException("unknown shell tool " + shellConfig.getShellTool());
    }
}