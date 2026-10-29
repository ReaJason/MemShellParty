package com.reajason.javaweb.fileless;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/** Defines the small JDK attach JNI bridge in its own loader so the native library is bound correctly. */
final class WindowsAttachBridge {
    private static final String GLOBAL_KEY =
            "com.reajason.javaweb.fileless.windows-attach-bridge";
    private static final String PROCESS_LOCK = (GLOBAL_KEY + ".lock").intern();
    private static volatile Class<?> cached;

    private WindowsAttachBridge() {
    }

    static void execute(byte[] stub) throws Exception {
        if (stub == null || stub.length == 0 || stub.length > 1000) {
            throw new IllegalArgumentException("Windows attach stub must contain 1 to 1000 bytes");
        }
        Class<?> bridge = bridge();
        long process = ((Long) invoke(bridge.getMethod("openProcess", Integer.TYPE),
                new Object[]{Integer.valueOf(currentProcessId())})).longValue();
        try {
            invoke(bridge.getMethod("run", byte[].class, Long.TYPE),
                    new Object[]{stub, Long.valueOf(process)});
        } finally {
            invoke(bridge.getMethod("closeProcess", Long.TYPE),
                    new Object[]{Long.valueOf(process)});
        }
    }

    private static String attachClassName() {
        try {
            Class.forName("sun.tools.attach.VirtualMachineImpl", false,
                    ClassLoader.getSystemClassLoader());
            return "sun.tools.attach.VirtualMachineImpl";
        } catch (ClassNotFoundException e) {
            return "sun.tools.attach.WindowsVirtualMachine";
        }
    }

    private static Object invoke(Method method, Object[] arguments) throws Exception {
        try {
            return method.invoke(null, arguments);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw e;
        }
    }

    private static int currentProcessId() {
        String name = ManagementFactory.getRuntimeMXBean().getName();
        int separator = name.indexOf('@');
        if (separator <= 0) {
            throw new UnsupportedOperationException("Could not identify the current Windows process");
        }
        return Integer.parseInt(name.substring(0, separator));
    }

    private static Class<?> bridge() throws Exception {
        Class<?> result = cached;
        if (result != null) {
            return result;
        }
        synchronized (PROCESS_LOCK) {
            result = cached;
            if (result != null) {
                return result;
            }
            Object shared = System.getProperties().get(GLOBAL_KEY);
            if (shared instanceof Class) {
                Method run = ((Class<?>) shared).getMethod("run", byte[].class, Long.TYPE);
                if (!attachClassName().equals(((Class<?>) shared).getName()) || run == null) {
                    throw new UnsupportedOperationException("Invalid shared Windows attach bridge");
                }
                cached = (Class<?>) shared;
                return cached;
            }
            result = new BridgeLoader(WindowsAttachBridge.class.getClassLoader())
                    .define(windowsVirtualMachineClass());
            System.getProperties().put(GLOBAL_KEY, result);
            cached = result;
            return result;
        }
    }

    static byte[] windowsVirtualMachineClass() throws IOException {
        return windowsVirtualMachineClass(attachClassName());
    }

    static byte[] windowsVirtualMachineClass(String attachClassName) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(512);
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeInt(0xcafebabe);
        out.writeShort(0);
        out.writeShort(50);
        out.writeShort(32);
        out.writeByte(7);
        out.writeShort(2);                              // 1: bridge class
        utf8(out, attachClassName.replace('.', '/'));
        out.writeByte(7);
        out.writeShort(4);                              // 3: Object
        utf8(out, "java/lang/Object");                 // 4
        utf8(out, "enqueue");                          // 5
        utf8(out, "(J[BLjava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V"); // 6
        utf8(out, "run");                              // 7
        utf8(out, "([BJ)V");                           // 8
        out.writeByte(8);
        out.writeShort(10);                             // 9: "attach"
        utf8(out, "attach");                           // 10
        out.writeByte(10);
        out.writeShort(12);
        out.writeShort(13);                             // 11: System.loadLibrary
        out.writeByte(7);
        out.writeShort(14);                             // 12: System
        out.writeByte(12);
        out.writeShort(15);
        out.writeShort(16);                             // 13: loadLibrary name/type
        utf8(out, "java/lang/System");                 // 14
        utf8(out, "loadLibrary");                      // 15
        utf8(out, "(Ljava/lang/String;)V");            // 16
        out.writeByte(8);
        out.writeShort(18);                             // 17: non-null attach data
        utf8(out, "test");                              // 18
        out.writeByte(10);
        out.writeShort(1);
        out.writeShort(20);                             // 19: bridge.enqueue
        out.writeByte(12);
        out.writeShort(5);
        out.writeShort(6);                              // 20: enqueue name/type
        utf8(out, "openProcess");                      // 21
        utf8(out, "(I)J");                             // 22
        out.writeByte(10);
        out.writeShort(1);
        out.writeShort(24);                             // 23: bridge.openProcess
        out.writeByte(12);
        out.writeShort(21);
        out.writeShort(22);                             // 24: openProcess name/type
        utf8(out, "closeProcess");                     // 25
        utf8(out, "(J)V");                             // 26
        out.writeByte(10);
        out.writeShort(1);
        out.writeShort(28);                             // 27: bridge.closeProcess
        out.writeByte(12);
        out.writeShort(25);
        out.writeShort(26);                             // 28: closeProcess name/type
        utf8(out, "Code");                             // 29
        utf8(out, "<clinit>");                         // 30
        utf8(out, "()V");                              // 31

        out.writeShort(0x0021);
        out.writeShort(1);
        out.writeShort(3);
        out.writeShort(0);                              // interfaces
        out.writeShort(0);                              // fields
        out.writeShort(5);                              // methods
        nativeMethod(out, 0x0189, 5, 6);                // enqueue
        nativeMethod(out, 0x0109, 21, 22);              // openProcess
        nativeMethod(out, 0x0109, 25, 26);              // closeProcess
        out.writeShort(0x0009);                         // public static run
        out.writeShort(7);
        out.writeShort(8);
        out.writeShort(1);
        out.writeShort(29);
        out.writeInt(31);
        out.writeShort(6);
        out.writeShort(3);
        out.writeInt(19);
        out.writeByte(0x12);
        out.writeByte(9);                               // ldc "attach"
        out.writeByte(0xb8);
        out.writeShort(11);                             // System.loadLibrary
        out.writeByte(0x1f);                            // lload_1
        out.writeByte(0x2a);                            // aload_0
        out.writeByte(0x12);
        out.writeByte(17);
        out.writeByte(0x12);
        out.writeByte(17);
        out.writeByte(0x03);                            // iconst_0
        out.writeByte(0xbd);
        out.writeShort(3);                              // anewarray Object
        out.writeByte(0xb8);
        out.writeShort(19);                             // enqueue
        out.writeByte(0xb1);                            // return
        out.writeShort(0);                              // exceptions
        out.writeShort(0);                              // code attributes
        out.writeShort(0x0008);                         // static <clinit>
        out.writeShort(30);
        out.writeShort(31);
        out.writeShort(1);
        out.writeShort(29);
        out.writeInt(18);
        out.writeShort(1);
        out.writeShort(0);
        out.writeInt(6);
        out.writeByte(0x12);
        out.writeByte(9);
        out.writeByte(0xb8);
        out.writeShort(11);
        out.writeByte(0xb1);
        out.writeShort(0);
        out.writeShort(0);
        out.writeShort(0);                              // class attributes
        out.flush();
        return bytes.toByteArray();
    }

    private static void nativeMethod(DataOutputStream out, int flags,
                                     int name, int descriptor) throws IOException {
        out.writeShort(flags);
        out.writeShort(name);
        out.writeShort(descriptor);
        out.writeShort(0);
    }

    private static void utf8(DataOutputStream out, String value) throws IOException {
        out.writeByte(1);
        out.writeUTF(value);
    }

    private static final class BridgeLoader extends ClassLoader {
        BridgeLoader(ClassLoader parent) {
            super(parent);
        }

        Class<?> define(byte[] bytes) {
            return defineClass(null, bytes, 0, bytes.length);
        }
    }
}
