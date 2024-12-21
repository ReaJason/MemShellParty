package com.reajason.javaweb.memshell.config;

import com.reajason.javaweb.memshell.utils.CommonUtil;
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
     * 注入器 Builder
     */
    DynamicType.Builder<?> injectorBuilder;
    /**
     * 内存马 Builder
     */
    DynamicType.Builder<?> shellBuilder;
    /**
     * 注入器模板类
     */
    private Class<?> injectorClass;
    /**
     * 注入器类名
     */
    @Builder.Default
    private String injectorClassName = CommonUtil.generateInjectorClassName();
    /**
     * 注入访问的地址
     */
    @Builder.Default
    private String urlPattern = "/*";
    /**
     * 内存马类名
     */
    private String shellClassName;
    /**
     * 内存马类字节
     */
    private byte[] shellClassBytes;
}
