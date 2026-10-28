package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HotSpotProfileProviderTest {

    @Test
    void keepsThePublicReflectiveEntryPoint() throws Exception {
        assertNotNull(HotSpotProfileProvider.class.getConstructor());
    }

    @Test
    void selectsVmStrategyWithoutVersionOrVendorWhitelists() {
        RuntimeFingerprint openJ9 = fingerprint("Eclipse OpenJ9 VM", "Linux", "amd64", "64");
        RuntimeFingerprint hotSpot = fingerprint("OpenJDK 64-Bit Server VM", "Linux", "amd64", "64");
        RuntimeFingerprint windows = fingerprint("OpenJDK 64-Bit Server VM", "Windows", "amd64", "64");
        RuntimeFingerprint aarch64 = fingerprint("OpenJDK 64-Bit Server VM", "Linux", "aarch64", "64");
        RuntimeFingerprint arm64 = fingerprint("OpenJDK 64-Bit Server VM", "Linux", "arm64", "64");

        assertTrue(openJ9.isOpenJ9());
        assertFalse(hotSpot.isOpenJ9());
        assertTrue(openJ9.isLinuxX86_64());
        assertFalse(windows.isLinuxX86_64());
        assertTrue(aarch64.isLinuxAarch64());
        assertTrue(arm64.isLinuxAarch64());
        assertFalse(aarch64.isLinuxX86_64());
    }

    private static RuntimeFingerprint fingerprint(String vm, String os, String arch, String model) {
        return new RuntimeFingerprint("arbitrary", "arbitrary", vm, "arbitrary", os, arch, model);
    }
}
