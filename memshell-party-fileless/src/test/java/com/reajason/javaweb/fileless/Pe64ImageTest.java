package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Pe64ImageTest {
    private static final long BASE = 0x180000000L;

    @Test
    void resolvesExportsAndOnlyReturnsCalleesWithExactRuntimeFunctionStarts() {
        Pe64Image image = Pe64Image.parseMapped(image(), BASE);
        Pe64Image.Function caller = image.exportFunction("Direct");

        assertEquals(0x1800, caller.begin);
        assertEquals(0x1810, caller.end);
        assertEquals(BASE + 0x1800, image.address(caller));
        Pe64Image.Function[] callees = image.directCallees(caller);
        assertEquals(1, callees.length);
        assertEquals(0x1820, callees[0].begin);
        assertEquals(0x1830, callees[0].end);
    }

    @Test
    void followsBoundedJniExportTailJumpWithoutRequiringWrapperPdata() {
        Pe64Image image = Pe64Image.parseMapped(image(), BASE);
        Pe64Image.Export wrapper = image.export("Agent_OnLoad");

        assertEquals(0x1900, wrapper.rva);
        assertThrows(UnsupportedOperationException.class, () -> image.exportFunction("Agent_OnLoad"));
        Pe64Image.Function target = image.directTailTarget(wrapper);
        assertEquals(0x1840, target.begin);
        assertEquals(0x1850, target.end);
    }

    @Test
    void rejectsForwardedExportsAndUnknownFunctions() {
        byte[] forwarded = image();
        put32(forwarded, 0x1100, 0x1028);
        Pe64Image image = Pe64Image.parseMapped(forwarded, BASE);

        assertThrows(UnsupportedOperationException.class, () -> image.export("Direct"));
        Pe64Image parsed = Pe64Image.parseMapped(image(), BASE);
        assertThrows(UnsupportedOperationException.class, () -> parsed.export("Missing"));
        assertThrows(UnsupportedOperationException.class, () -> parsed.functionAt(0x1801));
        assertThrows(UnsupportedOperationException.class, () -> parsed.functionAt(0x1900));
    }

    @Test
    void rejectsMalformedHeadersAndOverlappingRuntimeFunctions() {
        byte[] notAmd64 = image();
        put16(notAmd64, 0x84, 0x14c);
        assertThrows(UnsupportedOperationException.class,
                () -> Pe64Image.parseMapped(notAmd64, BASE));

        byte[] overlapping = image();
        put32(overlapping, 0x200c, 0x1808);
        assertThrows(UnsupportedOperationException.class,
                () -> Pe64Image.parseMapped(overlapping, BASE));

        byte[] noExceptionDirectory = image();
        put32(noExceptionDirectory, 0x98 + 112 + 3 * 8, 0);
        assertThrows(UnsupportedOperationException.class,
                () -> Pe64Image.parseMapped(noExceptionDirectory, BASE));
        assertThrows(UnsupportedOperationException.class,
                () -> Pe64Image.parseMapped(new byte[4096], BASE));
        assertThrows(UnsupportedOperationException.class,
                () -> Pe64Image.parseMapped(image(), 0));
    }

    @Test
    void detectsUniqueRipRelativeStringReference() {
        byte[] bytes = image();
        byte[] text = "sun/instrument/InstrumentationImpl".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(text, 0, bytes, 0x3000, text.length);
        bytes[0x1820] = 0x48;
        bytes[0x1821] = (byte) 0x8d;
        bytes[0x1822] = 0x0d;
        put32(bytes, 0x1823, 0x3000 - 0x1827);
        bytes[0x1827] = (byte) 0xc3;
        Pe64Image image = Pe64Image.parseMapped(bytes, BASE);

        assertTrue(image.referencesAscii(image.functionAt(0x1820),
                "sun/instrument/InstrumentationImpl"));
        assertEquals(0x1820, image.uniqueCalleeWithReference(image.functionAt(0x1800),
                "sun/instrument/InstrumentationImpl").begin);
    }

    private static byte[] image() {
        byte[] image = new byte[0x4000];
        put16(image, 0, 0x5a4d);
        put32(image, 0x3c, 0x80);
        put32(image, 0x80, 0x00004550);
        put16(image, 0x84, 0x8664);
        put16(image, 0x86, 1);
        put16(image, 0x94, 0xf0);
        put16(image, 0x98, 0x20b);
        put32(image, 0x98 + 56, image.length);
        put32(image, 0x98 + 108, 16);
        put32(image, 0x98 + 112, 0x1000);
        put32(image, 0x98 + 116, 0x100);
        put32(image, 0x98 + 112 + 3 * 8, 0x2000);
        put32(image, 0x98 + 112 + 3 * 8 + 4, 36);

        int section = 0x98 + 0xf0;
        put32(image, section + 8, 0x2000);
        put32(image, section + 12, 0x1000);
        put32(image, section + 36, 0x20000000);

        put32(image, 0x1000 + 20, 2);
        put32(image, 0x1000 + 24, 2);
        put32(image, 0x1000 + 28, 0x1100);
        put32(image, 0x1000 + 32, 0x1110);
        put32(image, 0x1000 + 36, 0x1118);
        put32(image, 0x1100, 0x1800);
        put32(image, 0x1104, 0x1900);
        put32(image, 0x1110, 0x1120);
        put32(image, 0x1114, 0x1140);
        put16(image, 0x1118, 0);
        put16(image, 0x111a, 1);
        ascii(image, 0x1120, "Direct");
        ascii(image, 0x1140, "Agent_OnLoad");

        runtimeFunction(image, 0x2000, 0x1800, 0x1810);
        runtimeFunction(image, 0x200c, 0x1820, 0x1830);
        runtimeFunction(image, 0x2018, 0x1840, 0x1850);
        Arrays.fill(image, 0x1800, 0x1905, (byte) 0x90);
        call(image, 0x1800, 0x1900);
        call(image, 0x1805, 0x1820);
        image[0x180a] = (byte) 0xc3;
        jump(image, 0x1900, 0x1840);
        return image;
    }

    private static void runtimeFunction(byte[] image, int offset, int begin, int end) {
        put32(image, offset, begin);
        put32(image, offset + 4, end);
        put32(image, offset + 8, 0);
    }

    private static void call(byte[] image, int offset, int target) {
        image[offset] = (byte) 0xe8;
        put32(image, offset + 1, target - (offset + 5));
    }

    private static void jump(byte[] image, int offset, int target) {
        image[offset] = (byte) 0xe9;
        put32(image, offset + 1, target - (offset + 5));
    }

    private static void ascii(byte[] image, int offset, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(bytes, 0, image, offset, bytes.length);
        image[offset + bytes.length] = 0;
    }

    private static void put16(byte[] image, int offset, int value) {
        image[offset] = (byte) value;
        image[offset + 1] = (byte) (value >>> 8);
    }

    private static void put32(byte[] image, int offset, int value) {
        put16(image, offset, value);
        put16(image, offset + 2, value >>> 16);
    }
}
