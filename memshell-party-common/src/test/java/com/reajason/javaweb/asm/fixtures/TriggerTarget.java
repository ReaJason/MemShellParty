package com.reajason.javaweb.asm.fixtures;

/**
 * 字节码工具测试夹具：构造方法 / toString / 静态初始化都会写系统属性，
 * 便于把改写后的类装进独立 ClassLoader 后观察代码是否真的执行。
 */
public class TriggerTarget {

    public static final String PROPERTY = "memshellparty.bytecode.test.trigger";
    public static final String CLINIT_PROPERTY = PROPERTY + ".clinit";

    public static String initialized = initialize();

    public TriggerTarget() {
        System.setProperty(PROPERTY, "noarg");
    }

    public TriggerTarget(String value) {
        System.setProperty(PROPERTY, "string:" + value);
    }

    @Override
    public String toString() {
        System.setProperty(PROPERTY, "toString");
        return "TriggerTarget";
    }

    private static String initialize() {
        System.setProperty(CLINIT_PROPERTY, "yes");
        return "initialized";
    }
}
