package com.reajason.javaweb.fileless;

import java.lang.instrument.Instrumentation;

/** Public reflective entry point; native addresses and layouts are resolved on every acquisition. */
public final class HotSpotProfileProvider implements InstrumentationProvider {
    public HotSpotProfileProvider() {
    }

    @Override
    public Instrumentation acquire() throws Exception {
        RuntimeFingerprint fingerprint = RuntimeFingerprint.detect();
        if (fingerprint.isWindowsX86_64()) {
            if (fingerprint.isOpenJ9()) {
                throw new UnsupportedOperationException("Windows native Instrumentation lookup requires HotSpot for "
                        + fingerprint + "; native state was not changed");
            }
            Class.forName("sun.instrument.InstrumentationImpl");
            return new WindowsInstrumentationProvider().acquire();
        }
        if (!fingerprint.isLinuxX86_64() && !fingerprint.isLinuxAarch64()) {
            throw new UnsupportedOperationException("Native Instrumentation lookup requires Linux/amd64, Linux/arm64 or Windows/amd64 for "
                    + fingerprint + "; native state was not changed");
        }
        Class.forName("sun.instrument.InstrumentationImpl");
        return new LinuxInstrumentationProvider().acquire();
    }
}
