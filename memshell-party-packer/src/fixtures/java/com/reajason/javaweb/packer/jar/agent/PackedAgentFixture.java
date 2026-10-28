package com.reajason.javaweb.packer.jar.agent;

import java.lang.instrument.Instrumentation;

public final class PackedAgentFixture {
    private PackedAgentFixture() {
    }

    public static void agentmain(String args, Instrumentation instrumentation) {
        PackedAgentLog.record(args, instrumentation, Thread.currentThread().getContextClassLoader());
    }
}
