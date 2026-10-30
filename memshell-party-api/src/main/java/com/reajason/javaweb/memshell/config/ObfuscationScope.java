package com.reajason.javaweb.memshell.config;

/**
 * 内存马生成物的混淆范围；仅在启用混淆时生效。
 */
public enum ObfuscationScope {
    /**
     * 主内存马、完整注入器产物组、辅助类与回显 Wrapper。
     */
    ALL,
    /**
     * 主内存马与完整注入器产物组，包括内部类、匿名类和持久化类。
     */
    MEMSHELL_INJECTOR,
    /**
     * 仅完整注入器产物组，包括内部类、匿名类和持久化类。
     */
    INJECTOR,
    /**
     * 仅主内存马。
     */
    MEMSHELL;

    public boolean includesMemshell() {
        return this != INJECTOR;
    }

    public boolean includesInjector() {
        return this != MEMSHELL;
    }

    public boolean includesHelperAndWrapper() {
        return this == ALL;
    }
}
