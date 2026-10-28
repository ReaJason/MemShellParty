package com.reajason.javaweb.fileless;

import java.io.RandomAccessFile;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.Arrays;

public final class NativeAgentFixture {
    private NativeAgentFixture() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            new HotSpotProfileProvider().acquire();
            return;
        }
        if (args.length != 2 && args.length != 4) {
            throw new IllegalArgumentException(
                    "Required arguments: [library:]offset capacity [triggerOffset triggerCapacity]");
        }
        RuntimeFingerprint fingerprint = RuntimeFingerprint.detect();
        Class.forName("sun.instrument.InstrumentationImpl");
        int regionCount = args.length / 2;
        NativeImage[] patches = new NativeImage[regionCount];
        long[] patchAddresses = new long[regionCount];
        byte[][] originalBytes = new byte[regionCount][];
        for (int region = 0; region < regionCount; region++) {
            String patchLibraryName = "libjvm.so";
            String patchOffsetValue = args[region * 2];
            int librarySeparator = patchOffsetValue.indexOf(':');
            if (librarySeparator > 0) {
                patchLibraryName = patchOffsetValue.substring(0, librarySeparator);
                patchOffsetValue = patchOffsetValue.substring(librarySeparator + 1);
            }
            patches[region] = NativeImage.findLinux(patchLibraryName);
            require(patches[region] != null, patchLibraryName + " is not mapped");
            patchAddresses[region] = patches[region].address(Long.decode(patchOffsetValue));
            originalBytes[region] = readMemory(
                    patchAddresses[region], Integer.decode(args[region * 2 + 1]));
        }
        System.out.println("FILELESS_RUNTIME=" + fingerprint);
        System.out.println("FILELESS_PATCH_PATH=" + patches[0].getFile().getAbsolutePath());
        Instrumentation instrumentation = null;
        for (int acquisition = 0; acquisition < 2; acquisition++) {
            instrumentation = new HotSpotProfileProvider().acquire();
            for (int region = 0; region < regionCount; region++) {
                require(Arrays.equals(originalBytes[region], readMemory(
                                patchAddresses[region], originalBytes[region].length)),
                        "Native region " + region + " was not restored after acquisition "
                                + (acquisition + 1));
            }
        }
        require(instrumentation.isRedefineClassesSupported(), "Redefine capability is missing");
        require(instrumentation.isRetransformClassesSupported(), "Retransform capability is missing");
        require(Target.value() == 7, "Target fixture must start unmodified");
        instrumentation.addTransformer(new TargetTransformer(), true);
        instrumentation.retransformClasses(Target.class);
        require(Target.value() == 8, "Retransformation did not change the target class");
        for (int region = 0; region < regionCount; region++) {
            patches[region].close();
        }
        System.out.println("NATIVE_JPLIS_RETRANSFORM_OK");
    }

    private static byte[] readMemory(long address, int length) throws Exception {
        RandomAccessFile memory = new RandomAccessFile("/proc/self/mem", "r");
        try {
            memory.seek(address);
            byte[] bytes = new byte[length];
            memory.readFully(bytes);
            return bytes;
        } finally {
            memory.close();
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    public static final class Target {
        private Target() {
        }

        public static int value() {
            return 7;
        }
    }

    public static final class TargetTransformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain, byte[] classfileBuffer)
                throws IllegalClassFormatException {
            if (classBeingRedefined == Target.class) {
                return RetransformFixture.replaceBipushReturn(classfileBuffer, 7, 8);
            }
            return null;
        }
    }
}
