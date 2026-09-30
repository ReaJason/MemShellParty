package com.reajason.javaweb.memshell.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.reajason.javaweb.utils.CommonUtil;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.bytebuddy.dynamic.DynamicType;

/**
 * @author ReaJason
 * @since 2024/12/5
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
public class InjectorConfig {
    /**
     * 注入器模板类
     */
    @JsonProperty(required = false)
    @JsonPropertyDescription("Injector template class; internal use, leave empty")
    private Class<?> injectorClass;

    /**
     * 注入器类名
     */
    @JsonProperty(required = false)
    @JsonPropertyDescription("Injector class name; random by default")
    @Builder.Default
    private String injectorClassName = CommonUtil.generateInjectorClassName();

    /**
     * 辅助类类名
     */
    @JsonProperty(required = false)
    @JsonPropertyDescription("Helper class name; derived from the injector class name by default")
    private String injectorHelperClassName;


    /**
     * 注入访问的地址
     */
    @JsonProperty(required = false)
    @JsonPropertyDescription("URL pattern the injected shell listens on. Defaults to /*")
    @Builder.Default
    private String urlPattern = "/*";

    /**
     * 内存马类名
     */
    @JsonProperty(required = false)
    @JsonPropertyDescription("Shell class name; random by default")
    private String shellClassName;

    /**
     * 内存马类字节
     */
    @JsonProperty(required = false)
    @JsonPropertyDescription("Shell class bytes; internal use, leave empty")
    private byte[] shellClassBytes;

    /**
     * 辅助类字节码
     */
    @JsonProperty(required = false)
    @JsonPropertyDescription("Helper class bytes; internal use, leave empty")
    private byte[] helperClassBytes;

    /**
     * 添加静态代码块调用构造方法初始化
     */
    @JsonProperty(required = false)
    @JsonPropertyDescription("Add a static initializer block that calls the constructor")
    private boolean staticInitialize;
}
