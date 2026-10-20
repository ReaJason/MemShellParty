package com.reajason.javaweb.godzilla;

/**
 * 装载器测试夹具：主类构造器依赖内部类，确保 B64Runner 先把 p1 里的内部类定义完，
 * 再定义/实例化主类时能解析到它。msg 字段与 toString 覆盖用于验证结果回传优先级。
 */
public class TestOuter {

    private static String msg = "";

    public TestOuter() {
        msg = "constructed:" + TestInner.value();
    }

    @Override
    public String toString() {
        return msg;
    }

    public static class TestInner {
        static String value() {
            return "inner-ok";
        }
    }
}
