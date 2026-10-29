package com.reajason.javaweb.fileless;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

/** Verifies the real packed bootstrap without making the fileless runtime available on the class path. */
public final class WindowsPackedAgentFixture {
    private WindowsPackedAgentFixture() {
    }

    public static void main(String[] args) throws Exception {
        require(NativeAgentFixture.Target.value() == 7, "Target fixture must start unmodified");
        BootstrapLoader loader = new BootstrapLoader(WindowsPackedAgentFixture.class.getClassLoader());
        byte[] bootstrap = readResource("packed-bootstrap.class");
        Class<?> type = loader.define(bootstrap);
        type.getConstructor().newInstance();
        require(NativeAgentFixture.Target.value() == 8,
                "Packed agent did not retransform the target class");
        System.out.println("WINDOWS_PACKED_FILELESS_RETRANSFORM_OK");
    }

    public static void agentmain(String args, Instrumentation instrumentation) throws Exception {
        require(instrumentation.isRedefineClassesSupported(), "Redefine capability is missing");
        require(instrumentation.isRetransformClassesSupported(), "Retransform capability is missing");
        instrumentation.addTransformer(new TargetTransformer(), true);
        instrumentation.retransformClasses(NativeAgentFixture.Target.class);
        require(NativeAgentFixture.Target.value() == 8,
                "Retransformation did not change the target class");
    }

    private static byte[] readResource(String name) throws IOException {
        InputStream input = WindowsPackedAgentFixture.class.getClassLoader().getResourceAsStream(name);
        if (input == null) {
            throw new IOException("Missing " + name);
        }
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        } finally {
            input.close();
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    public static final class TargetTransformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain, byte[] classfileBuffer)
                throws IllegalClassFormatException {
            if (classBeingRedefined == NativeAgentFixture.Target.class) {
                return RetransformFixture.replaceBipushReturn(classfileBuffer, 7, 8);
            }
            return null;
        }
    }

    private static final class BootstrapLoader extends ClassLoader {
        BootstrapLoader(ClassLoader parent) {
            super(parent);
        }

        Class<?> define(byte[] bytes) {
            return defineClass(null, bytes, 0, bytes.length);
        }
    }
}
