package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LinuxAcquisitionResolverTest {

    @Test
    void encodesX86RelativeJump() {
        assertArrayEquals(new byte[]{(byte) 0xe9, 0x0b, 0, 0, 0},
                LinuxAcquisitionResolver.directJump(false, 0x1000L, 0x1010L));
        assertArrayEquals(new byte[]{(byte) 0xe9, (byte) 0xfb, (byte) 0xef, (byte) 0xff, (byte) 0xff},
                LinuxAcquisitionResolver.directJump(false, 0x2000L, 0x1000L));
    }

    @Test
    void rejectsX86JumpOutsideRel32Range() {
        assertThrows(UnsupportedOperationException.class,
                () -> LinuxAcquisitionResolver.directJump(false, 0L, 0x80000005L));
    }

    @Test
    void encodesAArch64DirectBranch() {
        assertArrayEquals(new byte[]{0x04, 0x00, 0x00, 0x14},
                LinuxAcquisitionResolver.directJump(true, 0x1000L, 0x1010L));
        assertArrayEquals(new byte[]{0x00, (byte) 0xfc, (byte) 0xff, 0x17},
                LinuxAcquisitionResolver.directJump(true, 0x1000L, 0L));
    }

    @Test
    void rejectsMisalignedOrOutOfRangeAArch64Branch() {
        assertThrows(UnsupportedOperationException.class,
                () -> LinuxAcquisitionResolver.directJump(true, 0x1000L, 0x1002L));
        assertThrows(UnsupportedOperationException.class,
                () -> LinuxAcquisitionResolver.directJump(true, 0L, 0x8000000L));
    }
}
