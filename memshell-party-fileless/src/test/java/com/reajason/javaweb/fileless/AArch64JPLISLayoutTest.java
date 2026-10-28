package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AArch64JPLISLayoutTest {

    @Test
    void recoversPairedInstrumentationStoresFromIncomingAgent() {
        AArch64JPLISLayout.Layout layout = AArch64JPLISLayout.analyze(words(
                0xaa0103f7,
                0xa903e6fa,
                0xa904daf8,
                0xd65f03c0
        ), null, false);

        assertEquals(0x38, layout.instrumentationImplOffset);
        assertEquals(-1, layout.printWarningOffset);
    }

    @Test
    void recoversIndividualStoresAndRejectsClobberedBases() {
        ByteArrayOutputStream individual = new ByteArrayOutputStream();
        word(individual, 0xaa0103f7);
        for (int offset = 0x38; offset <= 0x50; offset += 8) {
            word(individual, 0xf9000000 | (offset / 8) << 10 | 23 << 5);
        }
        word(individual, 0xd65f03c0);
        assertEquals(0x38, AArch64JPLISLayout.analyze(
                individual.toByteArray(), null, false).instrumentationImplOffset);

        ByteArrayOutputStream clobbered = new ByteArrayOutputStream();
        word(clobbered, 0xaa0103f7);
        word(clobbered, 0x910006f7);
        byte[] stores = individual.toByteArray();
        for (int offset = 4; offset < stores.length; offset++) {
            clobbered.write(stores[offset]);
        }
        assertThrows(UnsupportedOperationException.class, () -> AArch64JPLISLayout.analyze(
                clobbered.toByteArray(), null, false));
    }

    @Test
    void rejectsCallerSavedUnknownAndEscapingPaths() {
        assertThrows(UnsupportedOperationException.class, () -> AArch64JPLISLayout.analyze(words(
                0xd63f0040,
                0xf900383f, 0xf900403f, 0xf900483f, 0xf900503f,
                0xd65f03c0
        ), null, false));
        assertThrows(UnsupportedOperationException.class, () -> AArch64JPLISLayout.analyze(words(
                0xaa0103f7, 0x00000000,
                0xa903e6fa, 0xa904daf8, 0xd65f03c0
        ), null, false));
        assertThrows(UnsupportedOperationException.class, () -> AArch64JPLISLayout.analyze(words(
                0x14000020, 0xd65f03c0
        ), null, false));
    }

    @Test
    void derivesAndCorroboratesWarningField() {
        byte[] create = words(
                0xaa0103f4,
                0xf9400267,
                0x3941e286,
                0xf94070e7,
                0xd63f00e0,
                0xa903e69a,
                0xa904de98,
                0xd65f03c0
        );
        byte[] initialize = words(0xaa0003f3, 0x3901e264, 0xd65f03c0);
        AArch64JPLISLayout.Layout layout = AArch64JPLISLayout.analyze(create, initialize, true);

        assertEquals(0x38, layout.instrumentationImplOffset);
        assertEquals(0x78, layout.printWarningOffset);
        assertThrows(UnsupportedOperationException.class, () -> AArch64JPLISLayout.analyze(
                create, words(0xaa0003f3, 0x3901e664, 0xd65f03c0), true));
    }

    @Test
    void corroboratesWarningFieldAcrossVectorZeroing() {
        byte[] create = words(
                0xaa0103f4,
                0xf9400267,
                0x3941e286,
                0xf94070e7,
                0xd63f00e0,
                0xa903e69a,
                0xa904de98,
                0xd65f03c0
        );
        byte[] initialize = words(
                0x4f000400,
                0xaa0003f3,
                0x3c838260,
                0x3c848260,
                0x3d801a60,
                0x3901e264,
                0xd65f03c0
        );

        AArch64JPLISLayout.Layout layout = AArch64JPLISLayout.analyze(create, initialize, true);

        assertEquals(0x38, layout.instrumentationImplOffset);
        assertEquals(0x78, layout.printWarningOffset);

        assertThrows(UnsupportedOperationException.class, () -> AArch64JPLISLayout.analyze(
                create, words(
                        0x4f000400,
                        0xaa0003f3,
                        0x3c820660,
                        0x3901e264,
                        0xd65f03c0
                ), true));
        assertThrows(UnsupportedOperationException.class, () -> AArch64JPLISLayout.analyze(
                create, words(
                        0x4f000400,
                        0xaa0003f3,
                        0x3c820e60,
                        0x3901e264,
                        0xd65f03c0
                ), true));
    }

    private static byte[] words(int... values) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (int value : values) {
            word(output, value);
        }
        return output.toByteArray();
    }

    private static void word(ByteArrayOutputStream output, int value) {
        output.write(value & 0xff);
        output.write((value >>> 8) & 0xff);
        output.write((value >>> 16) & 0xff);
        output.write((value >>> 24) & 0xff);
    }
}
