package com.reajason.javaweb.memshell.config;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import net.bytebuddy.description.type.TypeDescription;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
@Data
@SuperBuilder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class ShellToolConfig {
    /**
     * 模板类的二进制类名；生成时以字节方式读取，不会加载到 JVM，
     * 因此使用方无需引入模板所引用的第三方 API（servlet、spring 等）
     */
    private String shellTemplateClassName;

    @JsonIgnore
    private transient TypeDescription shellTypeDescription;

    /**
     * shellClass 的类名
     */
    private String shellClassName;
}