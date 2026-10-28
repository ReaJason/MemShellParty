package com.reajason.javaweb.fileless;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.Serializable;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Array;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Arrays;

final class LinuxInstrumentationProvider implements InstrumentationProvider {
    private static final String PROCESS_LOCK =
            "com.reajason.javaweb.fileless.native-acquire".intern();

    @Override
    public Instrumentation acquire() throws Exception {
        synchronized (PROCESS_LOCK) {
            LinuxAcquisitionResolver.AcquisitionPlan plan =
                    LinuxAcquisitionResolver.resolve();
            return acquireLocked(plan);
        }
    }

    private Instrumentation acquireLocked(LinuxAcquisitionResolver.AcquisitionPlan plan)
            throws Exception {
        return acquireLocked(plan, new RandomAccessFile("/proc/self/mem", "rw"));
    }

    static Instrumentation acquireLocked(LinuxAcquisitionResolver.AcquisitionPlan plan,
                                         RandomAccessFile memory) throws Exception {
        byte[] stub = plan.stub();
        byte[] expected = plan.expected();
        byte[] triggerStub = plan.triggerStub();
        byte[] triggerExpected = plan.triggerExpected();
        Instrumentation instrumentationTrigger = plan.instrumentationTrigger();
        Class<?> openJ9Trigger = instrumentationTrigger == null ? freshTrigger() : null;
        byte[] original = null;
        byte[] triggerOriginal = null;
        boolean restoreRequired = false;
        boolean triggerRestoreRequired = false;
        try {
            original = readAndVerify(memory, plan.patchAddress(), expected);
            if (triggerStub.length != 0) {
                triggerOriginal = readAndVerify(
                        memory, plan.triggerAddress(), triggerExpected);
            }
            restoreRequired = true;
            write(memory, plan.patchAddress(), stub);
            if (triggerStub.length != 0) {
                triggerRestoreRequired = true;
                write(memory, plan.triggerAddress(), triggerStub);
            }
            Object acquired = instrumentationTrigger == null
                    ? openJ9Trigger.getDeclaredClasses()
                    : instrumentationTrigger.getInitiatedClasses(null);
            if (!(acquired instanceof Instrumentation)) {
                throw new UnsupportedOperationException(
                        "JPLIS did not create a live Instrumentation instance; returned "
                                + (acquired == null ? "null" : acquired.getClass().getName()));
            }
            return (Instrumentation) acquired;
        } finally {
            try {
                if (triggerRestoreRequired) {
                    write(memory, plan.triggerAddress(), triggerOriginal);
                }
            } finally {
                try {
                    if (restoreRequired) {
                        write(memory, plan.patchAddress(), original);
                    }
                } finally {
                    memory.close();
                }
            }
        }
    }

    private static Class<?> freshTrigger() {
        // A fresh array class also avoids reflection caches on newer JDKs.
        ClassLoader loader = new URLClassLoader(new URL[0],
                LinuxInstrumentationProvider.class.getClassLoader());
        Class<?> proxy = Proxy.getProxyClass(loader, new Class<?>[]{Serializable.class});
        return Array.newInstance(proxy, 0).getClass();
    }

    static byte[] readAndVerify(RandomAccessFile memory, long address,
                                byte[] expected) throws IOException {
        byte[] original = new byte[expected.length];
        memory.seek(address);
        memory.readFully(original);
        if (!Arrays.equals(expected, original)) {
            throw new UnsupportedOperationException(
                    "Mapped native bytes differ from the resolved image; native state was not changed");
        }
        return original;
    }

    private static void write(RandomAccessFile memory, long address,
                              byte[] replacement) throws IOException {
        memory.seek(address);
        memory.write(replacement);
        byte[] actual = new byte[replacement.length];
        memory.seek(address);
        memory.readFully(actual);
        if (!Arrays.equals(replacement, actual)) {
            throw new IOException("Native memory verification failed");
        }
    }
}
