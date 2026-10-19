package com.reajason.javaweb.memshell.obfuscation.fixtures;

/**
 * 混淆测试夹具：模拟注入器内部类 / helper 类，持 outer 引用并调用其方法、访问其字段，
 * 用于验证跨类引用自动保护（方法名入黑名单、字段名混淆自动关闭）。
 */
public class InnerHelper {
    private final OuterClass outer;

    public InnerHelper(OuterClass outer) {
        this.outer = outer;
    }

    public String run() {
        return outer.outerCall() + outer.sharedField;
    }
}
