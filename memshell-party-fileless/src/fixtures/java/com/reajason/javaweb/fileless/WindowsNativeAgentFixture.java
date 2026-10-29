package com.reajason.javaweb.fileless;

import java.lang.instrument.Instrumentation;
import java.util.Arrays;

/** Real Windows verification without -javaagent or a helper DLL. */
public final class WindowsNativeAgentFixture {
    private WindowsNativeAgentFixture() {
    }

    public static void main(String[] args) throws Exception {
        WindowsAcquisitionResolver.AcquisitionPlan plan = WindowsAcquisitionResolver.resolve();
        byte[] hostOriginal = WindowsMemory.read(plan.patchAddress(), plan.expected().length);
        byte[] triggerOriginal = WindowsMemory.read(plan.triggerAddress(), plan.triggerExpected().length);
        System.out.println("FILELESS_RUNTIME=" + RuntimeFingerprint.detect());
        Instrumentation instrumentation = null;
        for (int acquisition = 0; acquisition < 2; acquisition++) {
            instrumentation = new HotSpotProfileProvider().acquire();
            require(Arrays.equals(hostOriginal,
                            WindowsMemory.read(plan.patchAddress(), hostOriginal.length)),
                    "Host bytes were not restored after acquisition " + (acquisition + 1));
            require(Arrays.equals(triggerOriginal,
                            WindowsMemory.read(plan.triggerAddress(), triggerOriginal.length)),
                    "Trigger bytes were not restored after acquisition " + (acquisition + 1));
        }
        require(instrumentation.isRedefineClassesSupported(), "Redefine capability is missing");
        require(instrumentation.isRetransformClassesSupported(), "Retransform capability is missing");
        require(NativeAgentFixture.Target.value() == 7, "Target fixture must start unmodified");
        instrumentation.addTransformer(new NativeAgentFixture.TargetTransformer(), true);
        instrumentation.retransformClasses(NativeAgentFixture.Target.class);
        require(NativeAgentFixture.Target.value() == 8,
                "Retransformation did not change the target class");
        System.out.println("WINDOWS_NATIVE_JPLIS_RETRANSFORM_OK");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
