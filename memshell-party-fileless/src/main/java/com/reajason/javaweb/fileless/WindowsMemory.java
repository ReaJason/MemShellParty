package com.reajason.javaweb.fileless;

import java.lang.reflect.Field;
import sun.misc.Unsafe;

/** Bounds-checked access to the current Windows process; no native helper library is required. */
final class WindowsMemory {
    private static final Unsafe UNSAFE = unsafe();

    private WindowsMemory() {
    }

    static byte[] read(long address, int length) {
        if (address == 0 || length < 0 || length > 256 * 1024 * 1024
                || address + length < address) {
            throw new IllegalArgumentException("Invalid native memory range");
        }
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = UNSAFE.getByte(address + i);
        }
        return result;
    }

    static long allocate(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Invalid native allocation size");
        }
        long address = UNSAFE.allocateMemory(length);
        UNSAFE.setMemory(address, length, (byte) 0);
        return address;
    }

    static long readLong(long address) {
        if (address == 0) {
            throw new IllegalArgumentException("Native address is required");
        }
        return UNSAFE.getLongVolatile(null, address);
    }

    static void free(long address) {
        if (address != 0) {
            UNSAFE.freeMemory(address);
        }
    }

    private static Unsafe unsafe() {
        try {
            Field field = Unsafe.class.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            return (Unsafe) field.get(null);
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }
}
