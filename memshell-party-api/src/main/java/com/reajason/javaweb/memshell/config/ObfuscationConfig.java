package com.reajason.javaweb.memshell.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 字节码混淆配置。
 *
 * @author ReaJason
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ObfuscationConfig implements Serializable {
    private static final long serialVersionUID = 1L;

    @JsonProperty(required = false)
    @JsonPropertyDescription("Whether to enable class obfuscation; disabled by default")
    @Builder.Default
    private boolean enabled = false;

    @JsonProperty(required = false)
    @JsonPropertyDescription("Obfuscation options to override default settings")
    @Builder.Default
    private Map<String, Object> options = new LinkedHashMap<>();

    public static ObfuscationConfig defaults() {
        return new ObfuscationConfig(false, new LinkedHashMap<>());
    }

    public static ObfuscationConfig enabled() {
        return new ObfuscationConfig(true, new LinkedHashMap<>());
    }

    public static ObfuscationConfig enabled(Map<String, Object> options) {
        return new ObfuscationConfig(true, options != null ? new LinkedHashMap<>(options) : new LinkedHashMap<>());
    }

    public Map<String, Object> getOptions() {
        if (options == null) {
            options = new LinkedHashMap<>();
        }
        return options;
    }
}
