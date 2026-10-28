package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.Test;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.ProtectionDomain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FilelessAgentBootstrapTest {

    @Test
    void rejectsInstrumentationWithoutRetransformBeforeLoadingAgent() {
        Instrumentation instrumentation = instrumentation(true, false);

        assertThrows(UnsupportedOperationException.class, () -> FilelessAgentBootstrap.install(
                "missing.agent.MustNotBeInitialized", null, instrumentation));
        assertFalse(ProbeAgent.called, "Agent code must not run after a failed capability check");
    }

    @Test
    void rejectsInstrumentationWithoutRedefineBeforeLoadingAgent() {
        Instrumentation instrumentation = instrumentation(false, true);

        assertThrows(UnsupportedOperationException.class, () -> FilelessAgentBootstrap.install(
                ProbeAgent.class.getName(), null, instrumentation));
        assertFalse(ProbeAgent.called);
    }

    @Test
    void invokesOneArgumentAgentmainFallback() throws Exception {
        FilelessAgentBootstrap.install(OneArgumentAgentmain.class.getName(), "agentmain-args",
                instrumentation(true, true));

        assertEquals("agentmain-args", OneArgumentAgentmain.args);
    }

    @Test
    void invokesOneArgumentPremainFallback() throws Exception {
        FilelessAgentBootstrap.install(OneArgumentPremain.class.getName(), "premain-args",
                instrumentation(true, true));

        assertEquals("premain-args", OneArgumentPremain.args);
    }

    @Test
    void restoresContextClassLoaderWhenAgentFails() throws Exception {
        Instrumentation instrumentation = instrumentation(true, true);
        ClassLoader original = Thread.currentThread().getContextClassLoader();
        ClassLoader agentLoader = new ClassLoader(original) {
        };
        Thread.currentThread().setContextClassLoader(agentLoader);
        try {
            assertThrows(IllegalStateException.class, () -> FilelessAgentBootstrap.install(
                    FailingAgent.class.getName(), "expected", instrumentation));
            assertTrue(FailingAgent.called);
            assertTrue(Thread.currentThread().getContextClassLoader() == agentLoader);
        } finally {
            Thread.currentThread().setContextClassLoader(original);
        }
    }

    @Test
    void rejectsUnknownRuntimeBeforeLoadingAgentWithoutInstrumentation() {
        assertThrows(UnsupportedOperationException.class, () -> FilelessAgentBootstrap.install(
                "missing.agent.MustNotBeInitialized", null));
    }

    static Instrumentation instrumentation(boolean redefine, boolean retransform) {
        return (Instrumentation) Proxy.newProxyInstance(
                FilelessAgentBootstrapTest.class.getClassLoader(),
                new Class<?>[]{Instrumentation.class},
                new CapabilityHandler(redefine, retransform));
    }

    private static final class CapabilityHandler implements InvocationHandler {
        private final boolean redefine;
        private final boolean retransform;

        private CapabilityHandler(boolean redefine, boolean retransform) {
            this.redefine = redefine;
            this.retransform = retransform;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            String name = method.getName();
            if ("isRedefineClassesSupported".equals(name)) {
                return redefine;
            }
            if ("isRetransformClassesSupported".equals(name)) {
                return retransform;
            }
            if ("toString".equals(name)) {
                return "InstrumentationFixture";
            }
            throw new AssertionError("Unexpected Instrumentation call before Agent installation: " + method);
        }
    }

    public static class ProbeAgent {
        private static boolean called;

        public static void agentmain(String args, Instrumentation instrumentation) {
            called = true;
        }
    }

    public static class OneArgumentAgentmain {
        private static String args;

        public static void agentmain(String args) {
            OneArgumentAgentmain.args = args;
        }
    }

    public static class OneArgumentPremain {
        private static String args;

        public static void premain(String args) {
            OneArgumentPremain.args = args;
        }
    }

    public static class FailingAgent {
        private static boolean called;

        public static void agentmain(String args, Instrumentation instrumentation) {
            called = true;
            if (Thread.currentThread().getContextClassLoader() != FailingAgent.class.getClassLoader()) {
                throw new AssertionError("Agent did not receive its own class loader as TCCL");
            }
            throw new IllegalStateException("expected");
        }
    }
}
