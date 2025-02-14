package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.memshell.packer.Packers;
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
    private Packers packer;

    @Data
    static class ShellToolConfigDTO {
        private String shellClassName;
        private String godzillaPass;
        private String godzillaKey;
        private String commandParamName;
        private String behinderPass;
        private String headerName;
        private String headerValue;
    }

    public ShellToolConfig parseShellToolConfig() {
        return switch (shellConfig.getShellTool()) {
            case Godzilla -> GodzillaConfig.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .pass(shellToolConfig.getGodzillaPass())
                    .key(shellToolConfig.getGodzillaKey())
                    .headerName(shellToolConfig.getHeaderName())
                    .headerValue(shellToolConfig.getHeaderValue())
                    .build();
            case Behinder -> BehinderConfig.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .pass(shellToolConfig.getBehinderPass())
                    .headerName(shellToolConfig.getHeaderName())
                    .headerValue(shellToolConfig.getHeaderValue())
                    .build();
            case Command -> CommandConfig.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .paramName(shellToolConfig.getCommandParamName())
                    .build();
            case Suo5 -> Suo5Config.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .headerName(shellToolConfig.getHeaderName())
                    .headerValue(shellToolConfig.getHeaderValue())
                    .build();
            default -> throw new UnsupportedOperationException("unknown shell tool " + shellConfig.getShellTool());
        };
    }
}