package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AArch64NativeStubTest {

    @Test
    void emitsBoundedAlignedStubWithWarningSupport() {
        byte[] stub = AArch64NativeStub.acquireInstrumentation(
                0x0000ffff00010000L, 0x0000ffff00020000L, 0x0000ffff00030000L,
                0x0000ffff00040000L, 0x0000ffff00050000L, 0x0000ffff00060000L,
                0x38, 0x78);

        assertEquals(0, stub.length & 3);
        assertTrue(stub.length <= 464);
        assertEquals(0xa9ba7bfd, word(stub, 0));
        assertEquals(0xd65f03c0, word(stub, stub.length - 4));
    }

    @Test
    void rejectsOffsetsOutsideTheValidatedLayout() {
        assertThrows(IllegalArgumentException.class, () -> AArch64NativeStub.acquireInstrumentation(
                1, 2, 3, 4, 5, 6, -1, -1));
        assertThrows(IllegalArgumentException.class, () -> AArch64NativeStub.acquireInstrumentation(
                1, 2, 3, 4, 5, 6, 0x38, 128));
    }

    private static int word(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) | (bytes[offset + 1] & 0xff) << 8
                | (bytes[offset + 2] & 0xff) << 16 | (bytes[offset + 3] & 0xff) << 24;
    }
}
