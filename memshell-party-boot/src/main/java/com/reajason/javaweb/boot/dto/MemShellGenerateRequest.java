package com.reajason.javaweb.boot.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.packer.Packers;
import lombok.Data;

import java.util.Map;

/**
 * 内存马生成请求。
 * <p>
 * {@code shellToolConfig} 直接用参数 map：key 就是工具 config 里 {@code @ConfigField} 字段的名字
 * （{@code pass} / {@code key} / {@code paramName}…），值统一是字符串，枚举传常量名。工具参数本来就是
 * 各工具自定义、SPI 插件还能自己加字段（如 GodzillaSession 的 {@code sessionKey}），写死成一个 DTO
 * 既盖不全插件字段，也要跟着每个新工具改一遍代码。
 *
 * @author ReaJason
 * @since 2024/12/18
 */
@Data
public class MemShellGenerateRequest {
    @JsonPropertyDescription("Target server, shell tool and shell type selection plus generation flags")
    private ShellConfig shellConfig;

    @JsonProperty(required = false)
    @JsonPropertyDescription("Shell-tool-specific options: keys are the shell tool's config field names (see shellToolConfigs in memshell_capabilities / GET /api/config/shelltool/configs), e.g. pass, key, paramName, template. Omit or leave blank to use random defaults; a key the chosen shellTool does not support is rejected.")
    private Map<String, String> shellToolConfig;

    @JsonProperty(required = false)
    @JsonPropertyDescription("Injector options such as urlPattern; may be omitted to use defaults")
    private InjectorConfig injectorConfig;

    @JsonPropertyDescription("Payload packer / output format, e.g. Base64, JSP, ScriptEngine, JavaDeserialize; see memshell_capabilities")
    private Packers packer;
}
