package com.reajason.javaweb.packer;

/**
 * 与具体打包器实现无关的判定工具。
 *
 * @author ReaJason
 */
public final class PackerSupport {

    private PackerSupport() {
    }

    /**
     * 判断类名是否正好位于 SpringGzipJDK17 系打包器要求的包下。
     */
    public static boolean isSpringExpressionClassName(String className) {
        if (className == null) {
            return false;
        }
        int lastDot = className.lastIndexOf('.');
        return lastDot > 0 && "org.springframework.expression".equals(className.substring(0, lastDot));
    }
}
