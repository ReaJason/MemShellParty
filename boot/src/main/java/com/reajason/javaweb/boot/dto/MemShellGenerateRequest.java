package com.reajason.javaweb.boot.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.packer.Packers;
import lombok.Data;

import static com.reajason.javaweb.memshell.ShellTool.*;

/**
 * @author ReaJason
 * @since 2024/12/18
 */
@Data
public class MemShellGenerateRequest {
    @JsonPropertyDescription("Target server, shell tool and shell type selection plus generation flags")
    private ShellConfig shellConfig;

    @JsonProperty(required = false)
    @JsonPropertyDescription("Shell-tool-specific options; may be omitted or empty to use random defaults")
    private ShellToolConfigDTO shellToolConfig;

    @JsonProperty(required = false)
    @JsonPropertyDescription("Injector options such as urlPattern; may be omitted to use defaults")
    private InjectorConfig injectorConfig;

    @JsonPropertyDescription("Payload packer / output format, e.g. Base64, JSP, ScriptEngine, JavaDeserialize; see memshell_capabilities")
    private Packers packer;

    @Data
    public static class ShellToolConfigDTO {
        @JsonProperty(required = false)
        @JsonPropertyDescription("Custom shell class name; random by default")
        private String shellClassName;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Godzilla password; random by default")
        private String godzillaPass;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Godzilla encryption key; random by default")
        private String godzillaKey;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Command shell request parameter name; random by default")
        private String commandParamName;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Command execution template containing a {command} placeholder; optional")
        private String commandTemplate;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Behinder password; random by default")
        private String behinderPass;

        @JsonProperty(required = false)
        @JsonPropertyDescription("AntSword password; random by default")
        private String antSwordPass;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Request header used to route to the shell, defaults to User-Agent (Referer for NeoreGeorg)")
        private String headerName;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Expected value of headerName; random by default")
        private String headerValue;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Base64-encoded custom shell class bytes; required when shellTool is Custom")
        private String shellClassBase64;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Command shell encryptor: RAW, BASE64 or DOUBLE_BASE64. Defaults to RAW")
        private String encryptor;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Command shell implementation: RuntimeExec or ForkAndExec. Defaults to RuntimeExec")
        private String implementationClass;
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
                    .headerName(shellToolConfig.getHeaderName())
                    .headerValue(shellToolConfig.getHeaderValue())
                    .template(shellToolConfig.getCommandTemplate())
                    .encryptor(CommandConfig.Encryptor.fromString(shellToolConfig.getEncryptor()))
                    .implementationClass(CommandConfig.ImplementationClass.fromString(shellToolConfig.getImplementationClass()))
                    .build();
            case Suo5, Suo5v2 -> Suo5Config.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .headerName(shellToolConfig.getHeaderName())
                    .headerValue(shellToolConfig.getHeaderValue())
                    .build();
            case AntSword -> AntSwordConfig.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .pass(shellToolConfig.getAntSwordPass())
                    .headerName(shellToolConfig.getHeaderName())
                    .headerValue(shellToolConfig.getHeaderValue())
                    .build();
            case NeoreGeorg -> NeoreGeorgConfig.builder()
                    .shellClassName(shellToolConfig.getShellClassName())
                    .headerName(shellToolConfig.getHeaderName())
                    .headerValue(shellToolConfig.getHeaderValue())
                    .build();
            case Custom -> CustomConfig.builder()
                    .shellClassBase64(shellToolConfig.getShellClassBase64())
                    .shellClassName(shellToolConfig.getShellClassName())
                    .build();
            case Proxy -> ProxyConfig.builder()
                    .headerName(shellToolConfig.getHeaderName())
                    .headerValue(shellToolConfig.getHeaderValue())
                    .shellClassName(shellToolConfig.shellClassName).build();
            default -> throw new UnsupportedOperationException("unknown shell tool " + shellConfig.getShellTool());
        };
    }
}