package com.reajason.javaweb.memshell.obfuscation;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serializable;
import java.util.Objects;

/**
 * 方法契约签名，用于指定混淆时不可改名的方法。
 *
 * @author ReaJason
 */
@Getter
@ToString
@EqualsAndHashCode
public final class MethodSignature implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String name;
    private final String descriptor; // 用于单测校验原始类结构完整性，为 null 时匹配任意重载

    private MethodSignature(String name, String descriptor) {
        this.name = Objects.requireNonNull(name, "method name must not be null");
        this.descriptor = descriptor;
    }

    public static MethodSignature of(String name, String descriptor) {
        return new MethodSignature(name, Objects.requireNonNull(descriptor, "descriptor must not be null"));
    }

    public static MethodSignature anyOverload(String name) {
        return new MethodSignature(name, null);
    }

    public String getName() {
        return name;
    }

    public String getDescriptor() {
        return descriptor;
    }
}
