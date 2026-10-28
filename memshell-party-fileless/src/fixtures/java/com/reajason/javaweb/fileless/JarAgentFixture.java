package com.reajason.javaweb.fileless;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;

public final class JarAgentFixture {
    private JarAgentFixture() {
    }

    public static final class Agent {
        public static final String INIT_PROPERTY = "memshell.fileless.test.initialized";
        public static volatile String args;
        public static volatile String resource;
        public static volatile Instrumentation instrumentation;
        public static volatile ClassLoader contextClassLoader;

        static {
            System.setProperty(INIT_PROPERTY, "true");
        }

        private Agent() {
        }

        public static void agentmain(String agentArgs, Instrumentation inst) throws Exception {
            args = agentArgs;
            instrumentation = inst;
            contextClassLoader = Thread.currentThread().getContextClassLoader();
            InputStream input = Agent.class.getResourceAsStream("/fixture/data.txt");
            if (input == null) {
                throw new IllegalStateException("Missing in-memory JAR resource");
            }
            try {
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                byte[] buffer = new byte[64];
                int length;
                while ((length = input.read(buffer)) != -1) {
                    output.write(buffer, 0, length);
                }
                resource = new String(output.toByteArray(), "UTF-8");
            } finally {
                input.close();
            }
        }
    }
}
