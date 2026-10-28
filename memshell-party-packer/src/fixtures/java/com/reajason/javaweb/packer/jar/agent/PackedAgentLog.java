package com.reajason.javaweb.packer.jar.agent;

import java.lang.instrument.Instrumentation;

public final class PackedAgentLog {
    static volatile String args;
    static volatile Instrumentation instrumentation;
    static volatile ClassLoader contextClassLoader;

    private PackedAgentLog() {
    }

    public static void record(String args, Instrumentation instrumentation, ClassLoader contextClassLoader) {
        PackedAgentLog.args = args;
        PackedAgentLog.instrumentation = instrumentation;
        PackedAgentLog.contextClassLoader = contextClassLoader;
    }
}
