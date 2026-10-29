package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WindowsX64StubTest {

    @Test
    void resolverKeepsOutputAndUsesTheCurrentPebNode() {
        byte[] stub = WindowsX64Stub.resolveModules(0x123456789abcdef0L);
        String hex = hex(stub);
        String output = "49bc" + littleEndianLong(0x123456789abcdef0L);

        assertTrue(stub.length > 128);
        assertTrue(stub.length <= 1000);
        assertTrue(hex.contains(output));
        assertEquals(-1, hex.indexOf("4989e4", hex.indexOf(output) + output.length()));
        assertTrue(hex.contains("488b5e20"));
        assertFalse(hex.contains("488b18"));
        assertTrue(hex.contains("65488b4160"));
        assertTrue(hex.contains("49c744242800010000"));
        assertEquals((byte) 0xc3, stub[stub.length - 1]);
    }

    @Test
    void memoryWriterUsesR15ForApiAndR14ForLengthWithWin64ShadowSpace() {
        byte[] stub = WindowsX64Stub.writeMemory(0x100, new byte[5], 0x200, 0x300, 0x400);
        String hex = hex(stub);

        assertTrue(hex.contains("49bf" + littleEndianLong(0x200)));
        assertTrue(hex.contains("48bb" + littleEndianLong(0x300)));
        assertTrue(hex.contains("49bc" + littleEndianLong(0x400)));
        assertTrue(hex.contains("49bd" + littleEndianLong(0x100)));
        assertTrue(hex.contains("49c7c605000000"));
        assertTrue(hex.contains("4589f1"));
        assertTrue(hex.contains("41ffd7"));
        assertTrue(hex.contains("4589f0"));
        assertTrue(hex.contains("ffd3"));
        assertTrue(hex.contains("41c644240001"));
        assertTrue(hex.contains("4883ec28"));
        assertTrue(hex.contains("4883c428"));
    }

    @Test
    void rejectsInvalidNativeReplacementsAndJplisOffsets() {
        assertThrows(IllegalArgumentException.class,
                () -> WindowsX64Stub.writeMemory(1, null, 2, 3, 4));
        assertThrows(IllegalArgumentException.class,
                () -> WindowsX64Stub.writeMemory(1, new byte[0], 2, 3, 4));
        assertThrows(IllegalArgumentException.class,
                () -> WindowsX64Stub.writeMemory(1, new byte[513], 2, 3, 4));
        assertThrows(IllegalArgumentException.class,
                () -> WindowsX64Stub.acquireInstrumentation(1, 2, 3, 4, 5, 6, -1, 0));
        assertThrows(IllegalArgumentException.class,
                () -> WindowsX64Stub.acquireInstrumentation(1, 2, 3, 4, 5, 6, 128, 0));
        assertThrows(IllegalArgumentException.class,
                () -> WindowsX64Stub.acquireInstrumentation(1, 2, 3, 4, 5, 6, 0, -2));
        assertThrows(IllegalArgumentException.class,
                () -> WindowsX64Stub.acquireInstrumentation(1, 2, 3, 4, 5, 6, 0, 128));
    }

    @Test
    void acquisitionStubContainsRealJniReturnSequenceAndAllResolvedAddresses() {
        byte[] stub = WindowsX64Stub.acquireInstrumentation(
                0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x38, 0x40);
        String hex = hex(stub);

        assertTrue(stub.length <= 1000);
        for (long address = 0x101; address <= 0x106; address++) {
            assertTrue(hex.contains("49bb" + littleEndianLong(address)));
        }
        assertTrue(hex.contains("4989cc"));
        assertTrue(hex.contains("4c89e1"));
        assertTrue(hex.contains("488b4038"));
        assertTrue(hex.contains("c6404000"));
        assertEquals((byte) 0xc3, stub[stub.length - 1]);
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format("%02x", value & 0xff));
        }
        return result.toString();
    }

    private static String littleEndianLong(long value) {
        StringBuilder result = new StringBuilder(16);
        for (int index = 0; index < 8; index++) {
            result.append(String.format("%02x", (value >>> (index * 8)) & 0xff));
        }
        return result.toString();
    }
}
