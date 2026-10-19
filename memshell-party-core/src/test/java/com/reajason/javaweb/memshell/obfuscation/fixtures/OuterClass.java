package com.reajason.javaweb.memshell.obfuscation.fixtures;

/**
 * 混淆测试夹具：方法名命中 CONSERVATIVE（doFilter）/ 自定义契约（outerCall）/ 自由改名（renameMe）三类，
 * 字段 sharedField 供跨类引用扫描触发 enableFieldName 自动关闭。
 */
public class OuterClass {
    /** 编译期常量：javac 以 ConstantValue 属性写入字段，class-obf 默认不会加密。 */
    public static final String STATIC_SECRET = "static-secret-3fT9";
    public static final String SECOND_SECRET = "second-secret-9Kp2";

    public String sharedField = "x";
    private int counter = 1;

    public String outerCall() {
        return "ok" + counter;
    }

    public String renameMe() {
        return "r";
    }

    public String doFilter() {
        return "f";
    }

    @Override
    public String toString() {
        return outerCall();
    }
}
