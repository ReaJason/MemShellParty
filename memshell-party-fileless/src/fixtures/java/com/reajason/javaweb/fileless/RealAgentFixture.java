package com.reajason.javaweb.fileless;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public final class RealAgentFixture {
    private RealAgentFixture() {
    }

    public static void main(String[] args) {
        require(RealAgentTargetAgent.called, "Agent entry point was not called");
        require("real-agent-args".equals(RealAgentTargetAgent.args), "Agent arguments were not preserved");
        require(RealAgentTargetAgent.retransformCapable, "Retransform capability is missing");
        require(RealAgentTargetAgent.transformerCalled, "Retransformation did not invoke the transformer");
        require(RealAgentTarget.value() == 8, "Fixture target was not modified by retransformation");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    public static final class Starter {
        private Starter() {
        }

        public static void premain(String args, Instrumentation instrumentation) throws Exception {
            FilelessAgentBootstrap.install(RealAgentTargetAgent.class.getName(), "real-agent-args", instrumentation);
        }
    }

    public static final class RealAgentTargetAgent {
        private static volatile boolean called;
        private static volatile boolean transformerCalled;
        private static volatile boolean retransformCapable;
        private static volatile String args;

        public static void agentmain(String agentArgs, Instrumentation instrumentation) throws Exception {
            called = true;
            args = agentArgs;
            retransformCapable = instrumentation.isRedefineClassesSupported()
                    && instrumentation.isRetransformClassesSupported();
            final String targetClassName = RealAgentTarget.class.getName().replace('.', '/');
            instrumentation.addTransformer(new ClassFileTransformer() {
                @Override
                public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                        ProtectionDomain protectionDomain, byte[] classfileBuffer)
                        throws IllegalClassFormatException {
                    if (targetClassName.equals(className)
                            && classBeingRedefined == RealAgentTarget.class) {
                        transformerCalled = true;
                        return RetransformFixture.replaceBipushReturn(classfileBuffer, 7, 8);
                    }
                    return null;
                }
            }, true);
            instrumentation.retransformClasses(RealAgentTarget.class);
        }
    }

    public static final class RealAgentTarget {
        private RealAgentTarget() {
        }

        public static int value() {
            return 7;
        }
    }
}
