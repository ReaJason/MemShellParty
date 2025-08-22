package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.utils.CommonUtil;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;

import static com.reajason.javaweb.memshell.ShellTool.*;

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
    static class ShellToolConfigDTO {
        private String shellClassName;
        private String godzillaPass;
        private String godzillaKey;
        private String commandParamName;
        private String behinderPass;
        private String antSwordPass;
        private String headerName;
        private String headerValue;
        private String shellClassBase64;
        private String encryptor;
        private String implementationClass;
    }

    public ShellToolConfig parseShellToolConfig() {
        return switch (shellConfig.getShellTool()) {
            case Godzilla -> GodzillaConfig.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .pass(StringUtils.defaultIfBlank(shellToolConfig.getGodzillaPass(), CommonUtil.getRandomString(8)))
                    .key(StringUtils.defaultIfBlank(shellToolConfig.getGodzillaKey(), CommonUtil.getRandomString(8)))
                    .headerName(shellToolConfig.getHeaderName())
                    .headerValue(StringUtils.defaultIfBlank(shellToolConfig.getHeaderValue(), CommonUtil.getRandomString(8)))
                    .build();
            case Behinder -> BehinderConfig.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .pass(StringUtils.defaultIfBlank(shellToolConfig.getBehinderPass(), CommonUtil.getRandomString(8)))
                    .headerName(shellToolConfig.getHeaderName())
                    .headerValue(StringUtils.defaultIfBlank(shellToolConfig.getHeaderValue(), CommonUtil.getRandomString(8)))
                    .build();
            case Command -> CommandConfig.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .paramName(StringUtils.defaultIfBlank(shellToolConfig.getCommandParamName(), CommonUtil.getRandomString(8)))
                    .encryptor(CommandConfig.Encryptor.fromString(shellToolConfig.getEncryptor()))
                    .implementationClass(CommandConfig.ImplementationClass.fromString(shellToolConfig.getImplementationClass()))
                    .build();
            case Suo5 -> Suo5Config.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .headerName(shellToolConfig.getHeaderName())
                    .headerValue(StringUtils.defaultIfBlank(shellToolConfig.getHeaderValue(), CommonUtil.getRandomString(8)))
                    .build();
            case AntSword -> AntSwordConfig.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .pass(StringUtils.defaultIfBlank(shellToolConfig.getAntSwordPass(), CommonUtil.getRandomString(8)))
                    .headerName(shellToolConfig.getHeaderName())
                    .headerValue(StringUtils.defaultIfBlank(shellToolConfig.getHeaderValue(), CommonUtil.getRandomString(8)))
                    .build();
            case NeoreGeorg -> NeoreGeorgConfig.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .headerName(shellToolConfig.getHeaderName())
                    .headerValue(StringUtils.defaultIfBlank(shellToolConfig.getHeaderValue(), CommonUtil.getRandomString(8)))
                    .build();
            case Custom -> CustomConfig.builder()
                    .shellClassBase64(shellToolConfig.getShellClassBase64())
                    .shellClassName(shellToolConfig.getShellClassName())
                    .build();
            default -> throw new UnsupportedOperationException("unknown shell tool " + shellConfig.getShellTool());
        };
    }
}