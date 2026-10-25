package com.reajason.javaweb.memshell;

/**
 * RawWebSocket shell 与注入器内置 helper 之间的命名约定。
 * <p>
 * helper 由 {@code AbstractServer.postProcessShellBytes} 按 shell 类名派生后随注入器下发，
 * shell 在运时用 {@code getClass().getName() + "$RawWsHelper"} 自行解析。shell 模板不能引用
 * 本类（目标容器里没有 api jar），其中的后缀字面量与本类必须保持一致。
 *
 * @author ReaJason
 */
public final class RawWsHelperNames {

    public static final String HELPER_SUFFIX = "$RawWsHelper";

    private RawWsHelperNames() {
    }

    public static String helperClassName(String shellClassName) {
        return shellClassName + HELPER_SUFFIX;
    }
}
