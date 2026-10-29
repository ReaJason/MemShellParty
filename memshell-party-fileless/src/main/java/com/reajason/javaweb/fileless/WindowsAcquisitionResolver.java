package com.reajason.javaweb.fileless;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/** Recovers the complete live-phase JPLIS sequence from the mapped Windows DLLs. */
final class WindowsAcquisitionResolver {
    private static final String HOTSPOT_MARKER = "JVM_GetDeclaredClasses";
    private static final String JNI_GET_CREATED = "JNI_GetCreatedJavaVMs";
    private static final String TRIGGER =
            "Java_sun_instrument_InstrumentationImpl_getInitiatedClasses0";
    private static final String HOST =
            "Java_sun_instrument_InstrumentationImpl_setNativeMethodPrefixes";

    private static final int GET_ENV = 0x30;
    private static final int GET_CAPABILITIES = 0x2c0;
    private static final int SET_EVENT_CALLBACKS = 0x3c8;
    private static final int ADD_CAPABILITIES = 0x468;
    private static final int SET_EVENT_NOTIFICATION = 0x8;
    private static final int SET_ENVIRONMENT_LOCAL_STORAGE = 0x498;

    private WindowsAcquisitionResolver() {
    }

    static AcquisitionPlan resolve() throws Exception {
        RuntimeFingerprint fingerprint = RuntimeFingerprint.detect();
        if (!fingerprint.isWindowsX86_64() || fingerprint.isOpenJ9()) {
            throw unsupported("Windows native acquisition requires a 64-bit HotSpot runtime");
        }
        Class.forName("sun.instrument.InstrumentationImpl"); // Loads the JDK's instrument.dll.
        long output = WindowsMemory.allocate(48);
        long jvmBase;
        long instrumentBase;
        long jniAddress;
        long writeProcessMemory;
        long flushInstructionCache;
        try {
            WindowsAttachBridge.execute(WindowsX64Stub.resolveModules(output));
            long status = WindowsMemory.readLong(output + 40);
            if (status != 0x100L) {
                throw unsupported("Could not resolve the current JVM and instrument DLLs; stage=" + status);
            }
            jvmBase = WindowsMemory.readLong(output);
            instrumentBase = WindowsMemory.readLong(output + 8);
            jniAddress = WindowsMemory.readLong(output + 16);
            writeProcessMemory = WindowsMemory.readLong(output + 24);
            flushInstructionCache = WindowsMemory.readLong(output + 32);
        } finally {
            WindowsMemory.free(output);
        }
        if (jvmBase == 0 || instrumentBase == 0 || jniAddress == 0
                || writeProcessMemory == 0 || flushInstructionCache == 0) {
            throw unsupported("Windows module resolution returned a null address");
        }
        Pe64Image jvm = Pe64Image.map(jvmBase);
        jvm.export(HOTSPOT_MARKER);
        if (jvm.address(jvm.export(JNI_GET_CREATED), 1) != jniAddress) {
            throw unsupported("Resolved JNI entry point conflicts with the mapped JVM export");
        }
        return resolveInstrument(Pe64Image.map(instrumentBase), jniAddress,
                writeProcessMemory, flushInstructionCache);
    }

    static AcquisitionPlan resolveInstrument(Pe64Image instrument, long jniAddress,
                                             long writeProcessMemory,
                                             long flushInstructionCache) throws Exception {
        Pe64Image.Function agentOnLoad = instrument.exportFunction("Agent_OnLoad");
        Pe64Image.Function agentOnAttach = instrument.exportFunction("Agent_OnAttach");
        Pe64Image.Function createNew = uniqueCalleeWithCalls(instrument, agentOnLoad,
                new int[]{GET_ENV}, "createNewJPLISAgent");
        Pe64Image.Function convertCapabilities = instrument.uniqueCalleeWithReference(
                agentOnLoad, "Can-Redefine-Classes");
        Pe64Image.Function createInstrumentation = instrument.uniqueCalleeWithReference(
                agentOnAttach, "sun/instrument/InstrumentationImpl");
        Pe64Image.Function setLive = uniqueCalleeWithCalls(instrument, agentOnAttach,
                new int[]{SET_EVENT_CALLBACKS, SET_EVENT_NOTIFICATION}, "setLivePhaseEventHandlers");

        Pe64Image.Function[] convertCalls = uniqueFunctions(
                instrument.directCallees(convertCapabilities));
        List<Pe64Image.Function> helpers = new ArrayList<Pe64Image.Function>();
        for (int i = 0; i < convertCalls.length; i++) {
            byte[] code = instrument.read(convertCalls[i]);
            if (X86_64JPLISLayout.hasIndirectCall(code, GET_CAPABILITIES)
                    && X86_64JPLISLayout.hasIndirectCall(code, ADD_CAPABILITIES)) {
                helpers.add(convertCalls[i]);
            }
        }
        Pe64Image.Function[] capabilityCalls = helpers.toArray(
                new Pe64Image.Function[helpers.size()]);
        int retransformIndex = -1;
        for (int i = 0; i < capabilityCalls.length; i++) {
            byte[] code = instrument.read(capabilityCalls[i]);
            if (X86_64JPLISLayout.hasIndirectCall(code, GET_ENV)
                    && X86_64JPLISLayout.hasIndirectCall(code, ADD_CAPABILITIES)) {
                if (retransformIndex >= 0) {
                    throw unsupported("Ambiguous retransformableEnvironment candidates");
                }
                retransformIndex = i;
            }
        }
        if (retransformIndex != 1) {
            throw unsupported("Capability helpers do not have the supported redefine/retransform order");
        }
        Pe64Image.Function addRedefine = capabilityCalls[0];
        Pe64Image.Function retransform = capabilityCalls[retransformIndex];
        requireCalls(instrument, addRedefine, GET_CAPABILITIES, ADD_CAPABILITIES);
        requireCalls(instrument, retransform, GET_CAPABILITIES, ADD_CAPABILITIES);

        boolean warningRequired = hasWarningConstructor();
        Pe64Image.Function initialize = warningRequired
                ? uniqueCalleeWithCalls(instrument, createNew,
                new int[]{SET_ENVIRONMENT_LOCAL_STORAGE}, "initializeJPLISAgent") : null;
        X86_64JPLISLayout.Layout layout = X86_64JPLISLayout.analyzeWindows(
                instrument.read(createInstrumentation),
                initialize == null ? null : instrument.read(initialize), warningRequired);

        Pe64Image.Function host = instrument.directTailTarget(instrument.export(HOST));
        Pe64Image.Export trigger = instrument.export(TRIGGER);
        byte[] stub = WindowsX64Stub.acquireInstrumentation(jniAddress,
                instrument.address(createNew), instrument.address(addRedefine),
                instrument.address(retransform), instrument.address(createInstrumentation),
                instrument.address(setLive), layout.instrumentationImplOffset,
                layout.printWarningOffset);
        if (stub.length > host.end - host.begin) {
            throw unsupported("Windows JPLIS initialization does not fit the resolved host");
        }
        long hostAddress = instrument.address(host);
        long triggerAddress = instrument.address(trigger, 5);
        byte[] triggerStub = directJump(triggerAddress, hostAddress);
        return new AcquisitionPlan(hostAddress, stub, instrument.read(host.begin, stub.length),
                triggerAddress, triggerStub, instrument.read(trigger, triggerStub.length),
                prepareInstrumentationTrigger(), writeProcessMemory, flushInstructionCache);
    }

    private static Pe64Image.Function uniqueCalleeWithCalls(Pe64Image image,
                                                             Pe64Image.Function caller,
                                                             int[] displacements,
                                                             String description) {
        Pe64Image.Function[] callees = image.directCallees(caller);
        Pe64Image.Function result = null;
        for (int i = 0; i < callees.length; i++) {
            byte[] code = image.read(callees[i]);
            boolean matches = true;
            for (int j = 0; j < displacements.length; j++) {
                matches &= X86_64JPLISLayout.hasIndirectCall(code, displacements[j]);
            }
            if (matches) {
                if (result != null && result.begin != callees[i].begin) {
                    throw unsupported("Ambiguous " + description + " candidates");
                }
                result = callees[i];
            }
        }
        if (result == null) {
            throw unsupported("Could not identify " + description);
        }
        return result;
    }

    private static Pe64Image.Function[] uniqueFunctions(Pe64Image.Function[] functions) {
        List<Pe64Image.Function> result = new ArrayList<Pe64Image.Function>();
        for (int i = 0; i < functions.length; i++) {
            boolean present = false;
            for (int j = 0; j < result.size(); j++) {
                present |= result.get(j).begin == functions[i].begin;
            }
            if (!present) {
                result.add(functions[i]);
            }
        }
        return result.toArray(new Pe64Image.Function[result.size()]);
    }

    private static void requireCalls(Pe64Image image, Pe64Image.Function function,
                                     int first, int second) {
        byte[] code = image.read(function);
        if (!X86_64JPLISLayout.hasIndirectCall(code, first)
                || !X86_64JPLISLayout.hasIndirectCall(code, second)) {
            throw unsupported("A recovered capability helper lacks its JVMTI calls");
        }
    }

    private static byte[] directJump(long source, long target) {
        long displacement = target - (source + 5L);
        if (displacement != (int) displacement) {
            throw unsupported("Windows trigger is outside the direct-jump range");
        }
        int relative = (int) displacement;
        return new byte[]{(byte) 0xe9, (byte) relative, (byte) (relative >>> 8),
                (byte) (relative >>> 16), (byte) (relative >>> 24)};
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
        private final long writeProcessMemory;
        private final long flushInstructionCache;

        AcquisitionPlan(long patchAddress, byte[] stub, byte[] expected,
                        long triggerAddress, byte[] triggerStub, byte[] triggerExpected,
                        Instrumentation instrumentationTrigger,
                        long writeProcessMemory, long flushInstructionCache) {
            if (patchAddress == 0 || triggerAddress == 0 || writeProcessMemory == 0
                    || flushInstructionCache == 0 || instrumentationTrigger == null
                    || stub == null || expected == null || stub.length == 0
                    || stub.length != expected.length || triggerStub == null
                    || triggerExpected == null || triggerStub.length != 5
                    || triggerStub.length != triggerExpected.length) {
                throw new IllegalArgumentException("Invalid Windows native acquisition plan");
            }
            this.patchAddress = patchAddress;
            this.stub = stub.clone();
            this.expected = expected.clone();
            this.triggerAddress = triggerAddress;
            this.triggerStub = triggerStub.clone();
            this.triggerExpected = triggerExpected.clone();
            this.instrumentationTrigger = instrumentationTrigger;
            this.writeProcessMemory = writeProcessMemory;
            this.flushInstructionCache = flushInstructionCache;
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

        long writeProcessMemory() {
            return writeProcessMemory;
        }

        long flushInstructionCache() {
            return flushInstructionCache;
        }
    }
}
