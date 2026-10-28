package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class X86_64JPLISLayoutTest {

    @Test
    void decodesDirectCallsTailJumpsAndJvmtiCalls() {
        X86_64JPLISLayout.Call[] calls = X86_64JPLISLayout.directCalls(
                new byte[]{(byte) 0xe8, 1, 0, 0, 0, (byte) 0xc3}, 0x1000L);
        assertEquals(1, calls.length);
        assertEquals(0, calls[0].offset);
        assertEquals(0x1006L, calls[0].target);
        assertEquals(0x2008L, X86_64JPLISLayout.directTailJump(
                new byte[]{0x55, 0x5d, (byte) 0xe9, 1, 0, 0, 0}, 0x2000L));
        X86_64JPLISLayout.Call[] outgoing = X86_64JPLISLayout.directCallsAndTailJumps(
                new byte[]{(byte) 0xe9, 1, 0, 0, 0, (byte) 0xe9, 1, 0, 0, 0}, 0x3000L);
        assertEquals(1, outgoing.length);
        assertEquals(5, outgoing[0].offset);
        assertEquals(0x300bL, outgoing[0].target);
        byte[] indirect = new byte[]{(byte) 0xff, (byte) 0x90,
                (byte) 0xc0, 0x02, 0, 0, (byte) 0xc3};
        assertTrue(X86_64JPLISLayout.hasIndirectCall(indirect, 0x2c0));
        assertFalse(X86_64JPLISLayout.hasIndirectCall(indirect, 0x468));
        assertTrue(X86_64JPLISLayout.hasOrImmediate(
                new byte[]{(byte) 0x80, 0x4d, (byte) 0xc1, 0x02}, 0x02));
        assertFalse(X86_64JPLISLayout.hasOrImmediate(
                new byte[]{(byte) 0x80, 0x4d, (byte) 0xd1, (byte) 0x80}, 0x02));
    }

    @Test
    void recoversInstrumentationFieldFromAgentProvenance() {
        X86_64JPLISLayout.Layout layout = X86_64JPLISLayout.analyze(createCode(), null, false);

        assertEquals(0x38, layout.instrumentationImplOffset);
        assertEquals(-1, layout.printWarningOffset);
    }

    @Test
    void recoversAgentFromStackSpillBeforeObjectStores() {
        X86_64JPLISLayout.Layout layout = X86_64JPLISLayout.analyze(new byte[]{
                0x55,
                0x48, (byte) 0x89, (byte) 0xe5,
                0x48, (byte) 0x89, 0x75, (byte) 0xc8,
                (byte) 0xe8, 0, 0, 0, 0,
                0x48, (byte) 0x8b, 0x4d, (byte) 0xc8,
                0x48, (byte) 0x89, 0x41, 0x38,
                0x48, (byte) 0x89, 0x51, 0x40,
                0x48, (byte) 0x89, 0x71, 0x48,
                0x48, (byte) 0x89, 0x79, 0x50,
                (byte) 0xc3
        }, null, false);

        assertEquals(0x38, layout.instrumentationImplOffset);
    }

    @Test
    void rejectsCallerSavedBaseClobberedByCall() {
        assertThrows(UnsupportedOperationException.class, () -> X86_64JPLISLayout.analyze(new byte[]{
                0x48, (byte) 0x89, (byte) 0xf1,
                (byte) 0xe8, 0, 0, 0, 0,
                0x48, (byte) 0x89, 0x41, 0x38,
                0x48, (byte) 0x89, 0x51, 0x40,
                0x48, (byte) 0x89, 0x71, 0x48,
                0x48, (byte) 0x89, 0x79, 0x50,
                (byte) 0xc3
        }, null, false));
    }
    @Test
    void rejectsInstructionsThatOverwriteAgentBase() {
        byte[][] clobbers = new byte[][]{
                {0x48, (byte) 0x8d, 0x1b},
                {0x0f, (byte) 0x95, (byte) 0xc3},
                {0x48, 0x03, (byte) 0xd8}
        };
        for (byte[] clobber : clobbers) {
            ByteArrayOutputStream code = new ByteArrayOutputStream();
            write(code, 0x48, 0x89, 0xf3);
            write(code, clobber);
            byte[] stores = createCode();
            write(code, Arrays.copyOfRange(stores, 3, stores.length));
            assertThrows(UnsupportedOperationException.class,
                    () -> X86_64JPLISLayout.analyze(code.toByteArray(), null, false));
        }
    }


    @Test
    void ignoresRegisterRestoreOnSeparateReturnPath() {
        X86_64JPLISLayout.Layout layout = X86_64JPLISLayout.analyze(new byte[]{
                0x49, (byte) 0x89, (byte) 0xf4,
                0x75, 0x03,
                0x41, 0x5c, (byte) 0xc3,
                0x49, (byte) 0x89, 0x44, 0x24, 0x38,
                0x49, (byte) 0x89, 0x4c, 0x24, 0x40,
                0x49, (byte) 0x89, 0x54, 0x24, 0x48,
                0x49, (byte) 0x89, 0x74, 0x24, 0x50,
                (byte) 0xc3
        }, null, false);

        assertEquals(0x38, layout.instrumentationImplOffset);
    }

    @Test
    void rejectsMissingOrAmbiguousAgentLayouts() {
        byte[] missingProvenance = createCode();
        byte[] withoutMov = Arrays.copyOfRange(missingProvenance, 3, missingProvenance.length);
        assertThrows(UnsupportedOperationException.class,
                () -> X86_64JPLISLayout.analyze(withoutMov, null, false));

        ByteArrayOutputStream ambiguous = new ByteArrayOutputStream();
        write(ambiguous, 0x49, 0x89, 0xf4); // mov rsi, r12
        write(ambiguous, createCode());
        write(ambiguous,
                0x49, 0x89, 0x44, 0x24, 0x38,
                0x49, 0x89, 0x4c, 0x24, 0x40,
                0x49, 0x89, 0x54, 0x24, 0x48,
                0x49, 0x89, 0x74, 0x24, 0x50,
                0xc3);
        assertThrows(UnsupportedOperationException.class,
                () -> X86_64JPLISLayout.analyze(ambiguous.toByteArray(), null, false));
    }

    @Test
    void rejectsUnknownInstructionsEscapingBranchesAndLargeOffsets() {
        ByteArrayOutputStream unknown = new ByteArrayOutputStream();
        write(unknown, createCode());
        write(unknown, 0x0f, 0x04);
        assertThrows(UnsupportedOperationException.class,
                () -> X86_64JPLISLayout.analyze(unknown.toByteArray(), null, false));

        ByteArrayOutputStream escaping = new ByteArrayOutputStream();
        write(escaping, createCode());
        write(escaping, 0x75, 0x20);
        assertThrows(UnsupportedOperationException.class,
                () -> X86_64JPLISLayout.analyze(escaping.toByteArray(), null, false));

        assertThrows(UnsupportedOperationException.class, () -> X86_64JPLISLayout.analyze(new byte[]{
                0x48, (byte) 0x89, (byte) 0xf3,
                0x48, (byte) 0x89, (byte) 0x83, (byte) 0x80, 0, 0, 0,
                0x48, (byte) 0x89, (byte) 0x8b, (byte) 0x88, 0, 0, 0,
                0x48, (byte) 0x89, (byte) 0x93, (byte) 0x90, 0, 0, 0,
                0x48, (byte) 0x89, (byte) 0xb3, (byte) 0x98, 0, 0, 0,
                (byte) 0xc3
        }, null, false));
    }

    @Test
    void derivesAndCorroboratesWarningField() {
        X86_64JPLISLayout.Layout layout = X86_64JPLISLayout.analyze(
                warningCreateCode(), warningInitCode(0x78), true);

        assertEquals(0x38, layout.instrumentationImplOffset);
        assertEquals(0x78, layout.printWarningOffset);
        assertThrows(UnsupportedOperationException.class, () -> X86_64JPLISLayout.analyze(
                warningCreateCode(), warningInitCode(0x79), true));
        assertThrows(UnsupportedOperationException.class,
                () -> X86_64JPLISLayout.analyze(createCode(), warningInitCode(0x78), true));
    }

    private static byte[] createCode() {
        ByteArrayOutputStream code = new ByteArrayOutputStream();
        write(code,
                0x48, 0x89, 0xf3,
                0x48, 0x89, 0x43, 0x40,
                0x48, 0x89, 0x4b, 0x48,
                0x48, 0x89, 0x53, 0x38,
                0x48, 0x89, 0x73, 0x50,
                0xb8, 1, 0, 0, 0,
                0xc3);
        return code.toByteArray();
    }

    private static byte[] warningCreateCode() {
        ByteArrayOutputStream code = new ByteArrayOutputStream();
        write(code,
                0x49, 0x89, 0xf5,
                0x41, 0x0f, 0xb6, 0x45, 0x78,
                0x50,
                0x41, 0xff, 0x92, 0xe0, 0, 0, 0,
                0x49, 0x89, 0x45, 0x38,
                0x49, 0x89, 0x4d, 0x40,
                0x49, 0x89, 0x55, 0x48,
                0x49, 0x89, 0x75, 0x50,
                0xc3);
        return code.toByteArray();
    }

    private static byte[] warningInitCode(int displacement) {
        return new byte[]{0x44, (byte) 0x88, 0x47, (byte) displacement, (byte) 0xc3};
    }

    private static void write(ByteArrayOutputStream output, byte[] bytes) {
        output.write(bytes, 0, bytes.length);
    }

    private static void write(ByteArrayOutputStream output, int... bytes) {
        for (int value : bytes) {
            output.write(value);
        }
    }
}
