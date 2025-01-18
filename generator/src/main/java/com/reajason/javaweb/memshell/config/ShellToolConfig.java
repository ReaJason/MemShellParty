package com.reajason.javaweb.memshell.config;

import com.reajason.javaweb.memshell.utils.CommonUtil;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public class ShellToolConfig {
    /**
     * 模板类 shellClass
     */
    private Class<?> shellClass;

    /**
     * shellClass 的类名
     */
    private String shellClassName;
}