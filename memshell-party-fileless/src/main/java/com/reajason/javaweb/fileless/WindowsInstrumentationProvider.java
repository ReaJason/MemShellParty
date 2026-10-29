package com.reajason.javaweb.fileless;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.util.Arrays;

final class WindowsInstrumentationProvider implements InstrumentationProvider {
    private static final String PROCESS_LOCK =
            "com.reajason.javaweb.fileless.native-acquire".intern();

    @Override
    public Instrumentation acquire() throws Exception {
        synchronized (PROCESS_LOCK) {
            return acquireLocked(WindowsAcquisitionResolver.resolve());
        }
    }

    static Instrumentation acquireLocked(WindowsAcquisitionResolver.AcquisitionPlan plan)
            throws Exception {
        byte[] stub = plan.stub();
        byte[] expected = plan.expected();
        byte[] triggerStub = plan.triggerStub();
        byte[] triggerExpected = plan.triggerExpected();
        byte[] original = null;
        byte[] triggerOriginal = null;
        boolean restoreRequired = false;
        boolean triggerRestoreRequired = false;
        try {
            original = readAndVerify(plan.patchAddress(), expected);
            triggerOriginal = readAndVerify(plan.triggerAddress(), triggerExpected);
            restoreRequired = true;
            write(plan, plan.patchAddress(), stub);
            triggerRestoreRequired = true;
            write(plan, plan.triggerAddress(), triggerStub);
            Object acquired = plan.instrumentationTrigger().getInitiatedClasses(null);
            if (!(acquired instanceof Instrumentation)) {
                throw new UnsupportedOperationException(
                        "JPLIS did not create a live Instrumentation instance; returned "
                                + (acquired == null ? "null" : acquired.getClass().getName()));
            }
            return (Instrumentation) acquired;
        } finally {
            try {
                if (triggerRestoreRequired) {
                    write(plan, plan.triggerAddress(), triggerOriginal);
                }
            } finally {
                if (restoreRequired) {
                    write(plan, plan.patchAddress(), original);
                }
            }
        }
    }

    static byte[] readAndVerify(long address, byte[] expected) {
        byte[] original = WindowsMemory.read(address, expected.length);
        if (!Arrays.equals(expected, original)) {
            throw new UnsupportedOperationException(
                    "Mapped native bytes differ from the resolved image; native state was not changed");
        }
        return original;
    }

    private static void write(WindowsAcquisitionResolver.AcquisitionPlan plan,
                              long address, byte[] replacement) throws Exception {
        long status = WindowsMemory.allocate(1);
        try {
            WindowsAttachBridge.execute(WindowsX64Stub.writeMemory(address, replacement,
                    plan.writeProcessMemory(), plan.flushInstructionCache(), status));
            if (WindowsMemory.read(status, 1)[0] != 1) {
                throw new IOException("Windows native memory write failed");
            }
            byte[] actual = WindowsMemory.read(address, replacement.length);
            if (!Arrays.equals(replacement, actual)) {
                throw new IOException("Windows native memory verification failed");
            }
        } finally {
            WindowsMemory.free(status);
        }
    }
}
