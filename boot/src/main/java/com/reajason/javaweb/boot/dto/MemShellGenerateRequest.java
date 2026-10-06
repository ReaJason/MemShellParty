package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.boot.service.ShellToolConfigMapper;
import com.reajason.javaweb.boot.service.ShellToolParams;
import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.packer.Packers;
import lombok.Data;

/**
 * @author ReaJason
 * @since 2024/12/18
 */
@Data
public class MemShellGenerateRequest {
    private ShellConfig shellConfig;
    private ShellToolConfigDTO shellToolConfig;
    private InjectorConfig injectorConfig;
    private Packers packer;

    @Data
    public static class ShellToolConfigDTO {
        private String shellClassName;
        private String godzillaPass;
        private String godzillaKey;
        private String commandParamName;
        private String commandTemplate;
        private String behinderPass;
        private String antSwordPass;
        private String headerName;
        private String headerValue;
        private String shellClassBase64;
        private String encryptor;
        private String implementationClass;
    }

    public ShellToolConfig parseShellToolConfig() {
        return ShellToolConfigMapper.map(shellConfig.getShellTool(), new ShellToolParams(
                shellToolConfig.getShellClassName(),
                shellToolConfig.getGodzillaPass(),
                shellToolConfig.getGodzillaKey(),
                shellToolConfig.getCommandParamName(),
                shellToolConfig.getCommandTemplate(),
                shellToolConfig.getBehinderPass(),
                shellToolConfig.getAntSwordPass(),
                shellToolConfig.getHeaderName(),
                shellToolConfig.getHeaderValue(),
                shellToolConfig.getShellClassBase64(),
                shellToolConfig.getEncryptor(),
                shellToolConfig.getImplementationClass()));
    }
}