package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class X86_64NativeStubTest {

    @Test
    void emitsStubThatFitsTheInstrumentationHost() {
        byte[] stub = X86_64NativeStub.acquireInstrumentation(
                0x0000ffff00010000L, 0x0000ffff00020000L, 0x0000ffff00030000L,
                0x0000ffff00040000L, 0x0000ffff00050000L, 0x0000ffff00060000L,
                0x38, 0x78);

        assertTrue(stub.length <= 317);
        assertArrayEquals(new byte[]{0x55, 0x48, (byte) 0x89, (byte) 0xe5},
                new byte[]{stub[0], stub[1], stub[2], stub[3]});
        assertEquals(0xc3, stub[stub.length - 1] & 0xff);
    }

    @Test
    void rejectsOffsetsOutsideTheValidatedLayout() {
        assertThrows(IllegalArgumentException.class, () -> X86_64NativeStub.acquireInstrumentation(
                1, 2, 3, 4, 5, 6, -1, -1));
        assertThrows(IllegalArgumentException.class, () -> X86_64NativeStub.acquireInstrumentation(
                1, 2, 3, 4, 5, 6, 0x38, 128));
    }
}
