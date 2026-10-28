package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.RandomAccessFile;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LinuxInstrumentationProviderTest {
    @TempDir
    Path directory;

    @Test
    void comparesTheWholePatchRegionBeforeAnyWrite() throws Exception {
        Path path = directory.resolve("memory.bin");
        byte[] original = new byte[]{1, 2, 3, 4, 5, 6};
        Files.write(path, original);
        RandomAccessFile memory = new RandomAccessFile(path.toFile(), "rw");
        try {
            assertThrows(UnsupportedOperationException.class, () -> LinuxInstrumentationProvider
                    .readAndVerify(memory, 0L, new byte[]{1, 2, 3, 4, 5, 7}));
            assertArrayEquals(original, LinuxInstrumentationProvider
                    .readAndVerify(memory, 0L, original));
        } finally {
            memory.close();
        }
        assertArrayEquals(original, Files.readAllBytes(path));
    }

    @Test
    void restoresBothRegionsAfterRepeatedTriggerFailures() throws Exception {
        Path path = memoryFile();
        byte[] original = Files.readAllBytes(path);
        Instrumentation trigger = trigger(path, true);
        LinuxAcquisitionResolver.AcquisitionPlan plan = plan(
                Arrays.copyOfRange(original, 32, 37), trigger);
        for (int acquisition = 0; acquisition < 2; acquisition++) {
            assertThrows(UnsupportedOperationException.class, () -> LinuxInstrumentationProvider
                    .acquireLocked(plan, new RandomAccessFile(path.toFile(), "rw")));
            assertArrayEquals(original, Files.readAllBytes(path));
        }
    }

    @Test
    void rejectsTriggerMismatchBeforeWritingEitherRegion() throws Exception {
        Path path = memoryFile();
        byte[] original = Files.readAllBytes(path);
        byte[] wrongTrigger = Arrays.copyOfRange(original, 32, 37);
        wrongTrigger[4]++;
        LinuxAcquisitionResolver.AcquisitionPlan plan = plan(wrongTrigger, trigger(path, false));

        assertThrows(UnsupportedOperationException.class, () -> LinuxInstrumentationProvider
                .acquireLocked(plan, new RandomAccessFile(path.toFile(), "rw")));
        assertArrayEquals(original, Files.readAllBytes(path));
    }

    @Test
    void restoresBothRegionsWhenInitializationFails() throws Exception {
        Path path = memoryFile();
        byte[] original = Files.readAllBytes(path);
        LinuxAcquisitionResolver.AcquisitionPlan plan = plan(
                Arrays.copyOfRange(original, 32, 37), trigger(path, true));

        assertThrows(UnsupportedOperationException.class, () -> LinuxInstrumentationProvider
                .acquireLocked(plan, new RandomAccessFile(path.toFile(), "rw")));
        assertArrayEquals(original, Files.readAllBytes(path));
    }

    private Path memoryFile() throws Exception {
        Path path = directory.resolve("double-patch-memory.bin");
        byte[] original = new byte[64];
        for (int i = 0; i < original.length; i++) {
            original[i] = (byte) i;
        }
        Files.write(path, original);
        return path;
    }

    private static LinuxAcquisitionResolver.AcquisitionPlan plan(
            byte[] triggerExpected, Instrumentation trigger) {
        return new LinuxAcquisitionResolver.AcquisitionPlan(
                8L, new byte[]{90, 91, 92, 93}, new byte[]{8, 9, 10, 11},
                32L, new byte[]{80, 81, 82, 83, 84}, triggerExpected, trigger);
    }

    private static Instrumentation trigger(Path path, boolean fail) {
        return (Instrumentation) Proxy.newProxyInstance(
                LinuxInstrumentationProviderTest.class.getClassLoader(),
                new Class<?>[]{Instrumentation.class}, new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                        if (!"getInitiatedClasses".equals(method.getName())) {
                            throw new UnsupportedOperationException(method.getName());
                        }
                        byte[] current = Files.readAllBytes(path);
                        assertArrayEquals(new byte[]{90, 91, 92, 93},
                                Arrays.copyOfRange(current, 8, 12));
                        assertArrayEquals(new byte[]{80, 81, 82, 83, 84},
                                Arrays.copyOfRange(current, 32, 37));
                        return fail ? null : proxy;
                    }
                });
    }
}
