package org.apache.dubbo.common.bytecode;

import javassist.ClassPool;

/**
 * Dubbo 2.7 {@code org.apache.dubbo.common.bytecode.ClassGenerator} 的生成期桩：注入器用它
 * 定位 Dubbo 的 ClassLoader、拿 Javassist 的 ClassPool，并把 {@code ClassGenerator.class} 当作
 * 类字面量与 ProtectionDomain 来源。
 *
 * @author ReaJason
 * @since 2026/10/20
 */
public final class ClassGenerator {

    public static ClassPool getClassPool(ClassLoader classLoader) {
        throw new UnsupportedOperationException();
    }
}
