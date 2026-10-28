package com.reajason.javaweb.fileless;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/** Builds a fresh, fully validated native acquisition plan on every invocation. */
final class LinuxAcquisitionResolver {
    private static final String JVM_LIBRARY = "libjvm.so";
    private static final String INSTRUMENT_LIBRARY = "libinstrument.so";
    private static final String HOTSPOT_MARKER = "JVM_GetDeclaredClasses";
    private static final String OPENJ9_TRIGGER = "Java_java_lang_Class_getDeclaredClassesImpl";
    private static final String INSTRUMENT_TRIGGER =
            "Java_sun_instrument_InstrumentationImpl_getInitiatedClasses0";
    private static final String INSTRUMENT_HOST = "setNativeMethodPrefixes";
    private static final String CREATE_INSTRUMENTATION = "createInstrumentationImpl";
    private static final String INITIALIZE_AGENT = "initializeJPLISAgent";

    private LinuxAcquisitionResolver() {
    }

    static AcquisitionPlan resolve() throws Exception {
        RuntimeFingerprint fingerprint = RuntimeFingerprint.detect();
        final boolean aarch64 = fingerprint.isLinuxAarch64();
        NativeImage jvm = null;
        NativeImage instrument = null;
        List<NativeImage> jvmImages = new ArrayList<NativeImage>();
        List<NativeImage> jclImages = new ArrayList<NativeImage>();
        try {
            jvmImages = NativeImage.findLinuxAll(JVM_LIBRARY);
            instrument = NativeImage.findLinux(INSTRUMENT_LIBRARY);
            if (jvmImages.isEmpty() || instrument == null) {
                throw unsupported("Mapped libjvm.so or libinstrument.so is unavailable");
            }
            List<Elf64File.Symbol[]> jvmSymbols = new ArrayList<Elf64File.Symbol[]>();
            Elf64File.Symbol jni = null;
            Elf64File.Symbol hotSpotMarker = null;
            boolean openJ9Runtime = fingerprint.isOpenJ9();
            int jniCandidates = 0;
            requireArchitecture(instrument, aarch64);
            for (int i = 0; i < jvmImages.size(); i++) {
                NativeImage image = jvmImages.get(i);
                requireArchitecture(image, aarch64);
                Elf64File.Symbol[] symbols = image.findSymbols(
                        new String[]{"JNI_GetCreatedJavaVMs", HOTSPOT_MARKER});
                jvmSymbols.add(symbols);
                if (symbols[0] != null) {
                    jniCandidates++;
                    jvm = image;
                    jni = symbols[0];
                }
                if (!openJ9Runtime && symbols[1] != null) {
                    if (hotSpotMarker != null) {
                        throw unsupported("Multiple HotSpot JVM candidates");
                    }
                    hotSpotMarker = symbols[1];
                }
            }
            jclImages = NativeImage.findLinuxFamily("libjclse");
            NativeImage openJ9Patch = null;
            Elf64File.Symbol openJ9Trigger = null;
            for (int i = 0; i < jclImages.size(); i++) {
                NativeImage candidate = jclImages.get(i);
                requireArchitecture(candidate, aarch64);
                Elf64File.Symbol symbol = candidate.findSymbol(OPENJ9_TRIGGER);
                if (symbol == null) {
                    continue;
                }
                if (openJ9Trigger != null) {
                    throw unsupported("Multiple OpenJ9 JNI trigger candidates");
                }
                openJ9Patch = candidate;
                openJ9Trigger = symbol;
            }
            if (openJ9Runtime && jniCandidates > 1) {
                jvm = null;
                jni = null;
                int coLocatedCandidates = 0;
                java.io.File jclParent = openJ9Patch == null
                        ? null : openJ9Patch.getFile().getParentFile();
                for (int i = 0; i < jvmImages.size(); i++) {
                    NativeImage candidateImage = jvmImages.get(i);
                    Elf64File.Symbol candidate = jvmSymbols.get(i)[0];
                    java.io.File parent = candidateImage.getFile().getParentFile();
                    if (candidate != null && parent != null && parent.equals(jclParent)) {
                        coLocatedCandidates++;
                        jvm = candidateImage;
                        jni = candidate;
                    }
                }
                if (coLocatedCandidates != 1) {
                    throw unsupported("Ambiguous OpenJ9 JVM/redirector candidates");
                }
            } else if (jniCandidates != 1) {
                throw unsupported(openJ9Runtime
                        ? "Multiple OpenJ9 JVM candidates" : "Multiple HotSpot JVM candidates");
            }
            jni = required(jni, "JNI_GetCreatedJavaVMs");

            if (hotSpotMarker != null && openJ9Trigger != null
                    || !openJ9Runtime && openJ9Trigger != null) {
                throw unsupported("Ambiguous HotSpot/OpenJ9 trigger strategies");
            }
            if (openJ9Runtime && openJ9Trigger == null) {
                throw unsupported("No supported JNI trigger symbol was found");
            }

            String[] instrumentNames = new String[]{
                    "createNewJPLISAgent", "addRedefineClassesCapability",
                    "retransformableEnvironment", CREATE_INSTRUMENTATION,
                    "setLivePhaseEventHandlers"
            };
            Elf64File.Symbol[] calls = instrument.findSymbols(instrumentNames);
            boolean warningRequired = hasWarningConstructor();
            X86_64StrippedJPLIS.Recovered recovered = null;
            boolean stripped = false;
            for (int i = 0; i < calls.length; i++) {
                stripped |= calls[i] == null;
            }
            Elf64File.Symbol initialize;
            int instrumentationImplOffset;
            int printWarningOffset;
            if (stripped) {
                if (aarch64) {
                    for (int i = 0; i < calls.length; i++) {
                        calls[i] = required(calls[i], instrumentNames[i]);
                    }
                }
                recovered = X86_64StrippedJPLIS.recover(instrument, warningRequired);
                Elf64File.Symbol[] recoveredCalls = new Elf64File.Symbol[]{
                        recovered.createNew, recovered.addRedefine,
                        recovered.retransformableEnvironment, recovered.createInstrumentation,
                        recovered.setLive
                };
                for (int i = 0; i < calls.length; i++) {
                    if (calls[i] != null && !sameFunction(calls[i], recoveredCalls[i])) {
                        throw unsupported("Stripped recovery conflicts with an existing JPLIS symbol");
                    }
                    calls[i] = recoveredCalls[i];
                }
                initialize = recovered.initialize;
                instrumentationImplOffset = recovered.layout.instrumentationImplOffset;
                printWarningOffset = recovered.layout.printWarningOffset;
            } else {
                for (int i = 0; i < calls.length; i++) {
                    calls[i] = required(calls[i], instrumentNames[i]);
                }
                initialize = warningRequired
                        ? required(instrument.findSymbol(INITIALIZE_AGENT), INITIALIZE_AGENT) : null;
                byte[] createCode = instrument.readFunction(calls[3]);
                byte[] initializeCode = warningRequired ? instrument.readFunction(initialize) : null;
                if (aarch64) {
                    AArch64JPLISLayout.Layout layout = AArch64JPLISLayout.analyze(
                            createCode, initializeCode, warningRequired);
                    instrumentationImplOffset = layout.instrumentationImplOffset;
                    printWarningOffset = layout.printWarningOffset;
                } else {
                    X86_64JPLISLayout.Layout layout = X86_64JPLISLayout.analyze(
                            createCode, initializeCode, warningRequired);
                    instrumentationImplOffset = layout.instrumentationImplOffset;
                    printWarningOffset = layout.printWarningOffset;
                }
            }

            NativeImage patch = openJ9Runtime ? openJ9Patch : instrument;
            Elf64File.Symbol patchSymbol = openJ9Runtime ? openJ9Trigger
                    : recovered != null ? recovered.host
                    : required(instrument.findSymbol(INSTRUMENT_HOST), INSTRUMENT_HOST);
            if (patchSymbol.size <= 0 || patchSymbol.size > Integer.MAX_VALUE) {
                throw unsupported("Invalid native host size");
            }
            byte[] stub = aarch64
                    ? AArch64NativeStub.acquireInstrumentation(
                    jvm.address(jni), instrument.address(calls[0]), instrument.address(calls[1]),
                    instrument.address(calls[2]), instrument.address(calls[3]),
                    instrument.address(calls[4]), instrumentationImplOffset, printWarningOffset)
                    : X86_64NativeStub.acquireInstrumentation(
                    jvm.address(jni), instrument.address(calls[0]), instrument.address(calls[1]),
                    instrument.address(calls[2]), instrument.address(calls[3]),
                    instrument.address(calls[4]), instrumentationImplOffset, printWarningOffset);
            if (stub.length > patchSymbol.size) {
                throw unsupported("Native initialization does not fit the resolved host");
            }
            long patchAddress = patch.address(patchSymbol);
            byte[] expected = patch.readPatch(patchSymbol, stub.length);

            long triggerAddress = 0L;
            byte[] triggerStub = new byte[0];
            byte[] triggerExpected = new byte[0];
            Instrumentation instrumentationTrigger = null;
            if (!openJ9Runtime) {
                Elf64File.Symbol trigger = required(
                        instrument.findSymbol(INSTRUMENT_TRIGGER), INSTRUMENT_TRIGGER);
                triggerAddress = instrument.address(trigger);
                triggerStub = directJump(aarch64, triggerAddress, patchAddress);
                triggerExpected = instrument.readPatch(trigger, triggerStub.length);
                instrumentationTrigger = prepareInstrumentationTrigger();
            }
            return new AcquisitionPlan(patchAddress, stub, expected,
                    triggerAddress, triggerStub, triggerExpected, instrumentationTrigger);
        } finally {
            close(instrument);
            for (int i = 0; i < jvmImages.size(); i++) {
                close(jvmImages.get(i));
            }
            for (int i = 0; i < jclImages.size(); i++) {
                close(jclImages.get(i));
            }
        }
    }

    static byte[] directJump(boolean aarch64, long source, long target) {
        if (aarch64) {
            long displacement = target - source;
            if ((displacement & 3L) != 0 || displacement < -0x8000000L
                    || displacement >= 0x8000000L) {
                throw unsupported("AArch64 trigger is outside the direct-branch range");
            }
            int instruction = 0x14000000 | (int) ((displacement >> 2) & 0x03ffffffL);
            return new byte[]{(byte) instruction, (byte) (instruction >>> 8),
                    (byte) (instruction >>> 16), (byte) (instruction >>> 24)};
        }
        long displacement = target - (source + 5L);
        if (displacement != (int) displacement) {
            throw unsupported("x86-64 trigger is outside the direct-jump range");
        }
        int relative = (int) displacement;
        return new byte[]{(byte) 0xe9, (byte) relative, (byte) (relative >>> 8),
                (byte) (relative >>> 16), (byte) (relative >>> 24)};
    }

    private static Instrumentation prepareInstrumentationTrigger() throws Exception {
        Class<?> implementation = Class.forName("sun.instrument.InstrumentationImpl");
        implementation.getMethod("getInitiatedClasses", ClassLoader.class);
        Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        Field singleton = unsafeClass.getDeclaredField("theUnsafe");
        singleton.setAccessible(true);
        Object unsafe = singleton.get(null);
        Object receiver = unsafeClass.getMethod("allocateInstance", Class.class)
                .invoke(unsafe, implementation);
        return (Instrumentation) receiver;
    }

    private static void requireArchitecture(NativeImage image, boolean aarch64) {
        if (image.isAarch64() != aarch64) {
            throw unsupported("Mapped ELF architecture differs from the Java runtime");
        }
    }

    private static boolean hasWarningConstructor() throws ClassNotFoundException {
        Constructor<?>[] constructors = Class.forName("sun.instrument.InstrumentationImpl")
                .getDeclaredConstructors();
        if (constructors.length != 1) {
            throw unsupported("Ambiguous InstrumentationImpl constructors");
        }
        int parameters = constructors[0].getParameterTypes().length;
        if (parameters == 3) {
            return false;
        }
        if (parameters == 4) {
            return true;
        }
        throw unsupported("Unsupported InstrumentationImpl constructor shape");
    }

    private static boolean sameFunction(Elf64File.Symbol first, Elf64File.Symbol second) {
        return first.value == second.value && first.size == second.size && first.type == second.type;
    }

    private static Elf64File.Symbol required(Elf64File.Symbol symbol, String name) {
        if (symbol == null) {
            throw unsupported("Required native symbol is missing: " + name);
        }
        return symbol;
    }

    private static void close(NativeImage image) {
        if (image != null) {
            try {
                image.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static UnsupportedOperationException unsupported(String message) {
        return new UnsupportedOperationException(message + "; native state was not changed");
    }

    static final class AcquisitionPlan {
        private final long patchAddress;
        private final byte[] stub;
        private final byte[] expected;
        private final long triggerAddress;
        private final byte[] triggerStub;
        private final byte[] triggerExpected;
        private final Instrumentation instrumentationTrigger;

        AcquisitionPlan(long patchAddress, byte[] stub, byte[] expected,
                        long triggerAddress, byte[] triggerStub, byte[] triggerExpected,
                        Instrumentation instrumentationTrigger) {
            this.patchAddress = patchAddress;
            this.stub = stub.clone();
            this.expected = expected.clone();
            this.triggerAddress = triggerAddress;
            this.triggerStub = triggerStub.clone();
            this.triggerExpected = triggerExpected.clone();
            this.instrumentationTrigger = instrumentationTrigger;
            if (this.stub.length == 0 || this.stub.length != this.expected.length
                    || this.triggerStub.length != this.triggerExpected.length
                    || (this.triggerStub.length == 0) != (instrumentationTrigger == null)) {
                throw new IllegalArgumentException("Invalid native acquisition plan");
            }
        }

        long patchAddress() {
            return patchAddress;
        }

        byte[] stub() {
            return stub.clone();
        }

        byte[] expected() {
            return expected.clone();
        }

        long triggerAddress() {
            return triggerAddress;
        }

        byte[] triggerStub() {
            return triggerStub.clone();
        }

        byte[] triggerExpected() {
            return triggerExpected.clone();
        }

        Instrumentation instrumentationTrigger() {
            return instrumentationTrigger;
        }
    }
}
