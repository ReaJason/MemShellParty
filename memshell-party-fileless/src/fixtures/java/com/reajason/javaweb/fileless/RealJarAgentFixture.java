package com.reajason.javaweb.fileless;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public final class RealJarAgentFixture {
    static final String CALLED_PROPERTY = "memshell.fileless.real.called";
    static final String ARGS_PROPERTY = "memshell.fileless.real.args";
    static final String CAPABLE_PROPERTY = "memshell.fileless.real.capable";
    static final String TRANSFORMED_PROPERTY = "memshell.fileless.real.transformed";

    private static volatile ClassLoader installedLoader;

    private RealJarAgentFixture() {
    }

    public static void main(String[] args) throws Exception {
        require(Boolean.getBoolean(CALLED_PROPERTY), "Agent entry point was not called");
        require("real-agent-args".equals(System.getProperty(ARGS_PROPERTY)), "Agent arguments were not preserved");
        require(Boolean.getBoolean(CAPABLE_PROPERTY), "Redefine/retransform capability is missing");
        require(Boolean.getBoolean(TRANSFORMED_PROPERTY), "Retransformation did not invoke the transformer");
        require(installedLoader instanceof JarLoader, "Agent was not loaded by the in-memory JarLoader");
        String targetClassName = RealJarAgentFixture.class.getName() + "$RealJarTarget";
        Class<?> target = installedLoader.loadClass(targetClassName);
        Object value = target.getMethod("value").invoke(null);
        require(Integer.valueOf(8).equals(value), "Fixture target was not modified by retransformation");
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
            InputStream input = Starter.class.getResourceAsStream("/target-agent.jar");
            if (input == null) {
                throw new IllegalStateException("Missing nested target Agent fixture");
            }
            byte[] jarBytes;
            try {
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int length;
                while ((length = input.read(buffer)) != -1) {
                    output.write(buffer, 0, length);
                }
                jarBytes = output.toByteArray();
            } finally {
                input.close();
            }
            installedLoader = FilelessAgentBootstrap.install(jarBytes, "real-agent-args",
                    instrumentation, Starter.class.getClassLoader());
        }
    }

    public static final class RealJarTargetAgent {
        private RealJarTargetAgent() {
        }

        public static void agentmain(String agentArgs, Instrumentation instrumentation) throws Exception {
            System.setProperty(CALLED_PROPERTY, "true");
            System.setProperty(ARGS_PROPERTY, agentArgs);
            System.setProperty(CAPABLE_PROPERTY, Boolean.toString(
                    instrumentation.isRedefineClassesSupported() && instrumentation.isRetransformClassesSupported()));
            String targetClassName = RealJarTarget.class.getName().replace('.', '/');
            instrumentation.addTransformer(new RealJarTargetTransformer(targetClassName), true);
            instrumentation.retransformClasses(RealJarTarget.class);
        }
    }

    public static final class RealJarTargetTransformer implements ClassFileTransformer {
        private final String targetClassName;

        public RealJarTargetTransformer(String targetClassName) {
            this.targetClassName = targetClassName;
        }

        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain, byte[] classfileBuffer)
                throws IllegalClassFormatException {
            if (targetClassName.equals(className) && classBeingRedefined == RealJarTarget.class) {
                System.setProperty(TRANSFORMED_PROPERTY, "true");
                return RetransformFixture.replaceBipushReturn(classfileBuffer, 7, 8);
            }
            return null;
        }
    }

    public static final class RealJarTarget {
        private RealJarTarget() {
        }

        public static int value() {
            return 7;
        }
    }
}
