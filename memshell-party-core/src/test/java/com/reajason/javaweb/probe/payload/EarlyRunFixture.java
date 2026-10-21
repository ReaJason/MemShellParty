package com.reajason.javaweb.probe.payload;

/**
 * ResponseEarlyRunTest 的内嵌字节码：构造时写 JVM 级标记（System property），
 * toString 返回固定串供回显断言。必须只依赖 JDK：由 ByteCodeProbe 在独立
 * URLClassLoader 中 defineClass + newInstance 执行。
 */
public class EarlyRunFixture {

    public static final String MARKER_KEY = "memparty.earlyRun.marker";
    public static final String MARKER_VALUE = "early-run-executed";
    public static final String ECHO_TEXT = "early-run-echo-ok";

    public EarlyRunFixture() {
        System.setProperty(MARKER_KEY, MARKER_VALUE);
    }

    @Override
    public String toString() {
        return ECHO_TEXT;
    }
}
