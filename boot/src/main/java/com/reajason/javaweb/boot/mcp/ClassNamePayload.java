package com.reajason.javaweb.boot.mcp;

/**
 * {@code parse_class_name} 的返回值。
 *
 * @param className 从字节码解析出的全限定类名
 * @author ReaJason
 */
public record ClassNamePayload(String className) {
}
