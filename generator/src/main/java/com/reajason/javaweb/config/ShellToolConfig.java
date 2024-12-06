package com.reajason.javaweb.config;

import com.reajason.javaweb.util.CommonUtil;
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
    private Class<?> clazz;

    /**
     * shellClass 的类名
     */
    @Builder.Default
    private String className = CommonUtil.generateShellClassName();
}