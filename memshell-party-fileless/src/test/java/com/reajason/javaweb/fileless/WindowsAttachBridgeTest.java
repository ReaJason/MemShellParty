package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WindowsAttachBridgeTest {

    @Test
    void generatesJavaSixBridgeForBothJdkAttachClassNames() throws Exception {
        assertBridge("sun.tools.attach.WindowsVirtualMachine");
        assertBridge("sun.tools.attach.VirtualMachineImpl");
    }

    private static void assertBridge(String className) throws Exception {
        byte[] bytes = WindowsAttachBridge.windowsVirtualMachineClass(className);
        assertEquals(50, readUnsignedShort(bytes, 6));
        Class<?> type = new Loader().define(bytes);

        assertEquals(className, type.getName());
        Method enqueue = type.getMethod("enqueue", Long.TYPE, byte[].class,
                String.class, String.class, Object[].class);
        Method openProcess = type.getMethod("openProcess", Integer.TYPE);
        Method closeProcess = type.getMethod("closeProcess", Long.TYPE);
        Method run = type.getMethod("run", byte[].class, Long.TYPE);
        assertTrue(Modifier.isNative(enqueue.getModifiers()));
        assertTrue(Modifier.isNative(openProcess.getModifiers()));
        assertTrue(Modifier.isNative(closeProcess.getModifiers()));
        assertTrue(Modifier.isStatic(enqueue.getModifiers()));
        assertTrue(Modifier.isStatic(openProcess.getModifiers()));
        assertTrue(Modifier.isStatic(closeProcess.getModifiers()));
        assertEquals(Long.TYPE, openProcess.getReturnType());
        assertEquals(Void.TYPE, enqueue.getReturnType());
        assertEquals(Void.TYPE, closeProcess.getReturnType());
        assertEquals(Void.TYPE, run.getReturnType());
        assertTrue(!Modifier.isNative(run.getModifiers()));
    }

    private static int readUnsignedShort(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) << 8 | bytes[offset + 1] & 0xff;
    }

    private static final class Loader extends ClassLoader {
        Loader() {
            super(null);
        }

        Class<?> define(byte[] bytes) {
            return defineClass(null, bytes, 0, bytes.length);
        }
    }
}
