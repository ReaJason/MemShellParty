package com.reajason.javaweb.fileless;

import java.lang.instrument.Instrumentation;

/** Public reflective entry point; native addresses and layouts are resolved on every acquisition. */
public final class HotSpotProfileProvider implements InstrumentationProvider {
    public HotSpotProfileProvider() {
    }

    @Override
    public Instrumentation acquire() throws Exception {
        RuntimeFingerprint fingerprint = RuntimeFingerprint.detect();
        if (!fingerprint.isLinuxX86_64() && !fingerprint.isLinuxAarch64()) {
            throw new UnsupportedOperationException("Native Instrumentation lookup requires Linux/amd64 or Linux/arm64 for "
                    + fingerprint + "; native state was not changed");
        }
        Class.forName("sun.instrument.InstrumentationImpl");
        return new LinuxInstrumentationProvider().acquire();
    }
}
