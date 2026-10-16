package com.reajason.javaweb.woodpecker;

import me.gv7.woodpecker.plugin.IResultOutput;

import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * 插件执行外壳：类加载器切换 + 统一异常出口。
 *
 * <p>类加载器：{@code MemShellRegistry} 用 {@code ServiceLoader}（单参重载，按线程上下文类加载器）
 * 发现 server/shelltool provider。框架调用插件时线程上下文仍是框架自己的类加载器，而 provider 都在
 * 插件 jar 里，不换上下文就会一个 provider 都发现不到（表现为「不支持的 server」）。
 *
 * <p>异常：框架只把 {@code doHelp} 抛出的异常打到控制台，界面上什么都没有，所以这里兜住全部
 * Throwable 并翻译成可读提示（含异常信息与参数线索），只有堆栈走 debugPrintln。
 */
final class PluginRuntime {

    interface Task {
        void run(IResultOutput output) throws Throwable;
    }

    private PluginRuntime() {
    }

    static void run(IResultOutput output, Task task) {
        ClassLoader previous = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(PluginRuntime.class.getClassLoader());
        try {
            task.run(output);
        } catch (Throwable t) {
            output.failPrintln("生成失败：" + describe(t));
            output.debugPrintln(stackTrace(t));
        } finally {
            Thread.currentThread().setContextClassLoader(previous);
        }
    }

    private static String describe(Throwable t) {
        String message = t.getMessage();
        if (message == null || message.trim().isEmpty()) {
            return t.getClass().getName() + "（详见调试信息）";
        }
        return message;
    }

    private static String stackTrace(Throwable t) {
        StringWriter writer = new StringWriter();
        PrintWriter printer = new PrintWriter(writer);
        t.printStackTrace(printer);
        printer.flush();
        return writer.toString();
    }
}
