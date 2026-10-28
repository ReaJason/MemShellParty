package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Elf64FileTest {
    @TempDir
    Path directory;

    @Test
    void resolvesSymtabAndDynsymThroughPtLoad() throws Exception {
        ElfBuilder symtab = new ElfBuilder().sym(spec("target", 0x1100, 16, 1, 2));
        Elf64File symtabFile = open("symtab.so", symtab.build());
        Elf64File.Symbol fromSymtab = symtabFile.findSymbol("target");
        assertArrayEquals(symtab.text, symtabFile.readFunction(fromSymtab));
        symtabFile.close();

        ElfBuilder dynsym = new ElfBuilder().dyn(spec("target", 0x1100, 16, 1, 2));
        Elf64File dynsymFile = open("dynsym.so", dynsym.build());
        assertArrayEquals(dynsym.text, dynsymFile.readFunction(dynsymFile.findSymbol("target")));
        dynsymFile.close();
    }

    @Test
    void acceptsConsistentMirrorsAndRejectsConflicts() throws Exception {
        Spec target = spec("target", 0x1100, 16, 1, 2);
        Elf64File mirrored = open("mirrored.so", new ElfBuilder().sym(target).dyn(target).build());
        assertEquals(0x1100, mirrored.findSymbol("target").value);
        mirrored.close();

        Elf64File conflicting = open("conflicting.so", new ElfBuilder().sym(target)
                .dyn(spec("target", 0x1110, 16, 1, 2)).build());
        assertThrows(UnsupportedOperationException.class, () -> conflicting.findSymbol("target"));
        conflicting.close();
    }

    @Test
    void rejectsMissingUndefinedNonFunctionIfuncAndZeroSizedFunctions() throws Exception {
        Elf64File missing = open("missing.so", new ElfBuilder().build());
        assertNull(missing.findSymbol("target"));
        missing.close();

        assertInvalidSymbol("undefined.so", spec("target", 0x1100, 16, 0, 2));
        assertInvalidSymbol("object.so", spec("target", 0x1100, 16, 1, 1));
        assertInvalidSymbol("ifunc.so", spec("target", 0x1100, 16, 1, 10));

        Elf64File zero = open("zero.so", new ElfBuilder()
                .sym(spec("target", 0x1100, 0, 1, 2)).build());
        Elf64File.Symbol symbol = zero.findSymbol("target");
        assertThrows(UnsupportedOperationException.class, () -> zero.readFunction(symbol));
        zero.close();
    }

    @Test
    void acceptsAarch64SharedObjects() throws Exception {
        byte[] bytes = new ElfBuilder().sym(spec("target", 0x1100, 16, 1, 2)).build();
        put16(bytes, 18, 183);
        Elf64File file = open("aarch64.so", bytes);
        assertTrue(file.isAarch64());
        assertEquals(0x1100, file.findSymbol("target").value);
        file.close();
    }

    @Test
    void rejectsMalformedHeadersTablesStringsAndOverflow() throws Exception {
        byte[] wrongArchitecture = new ElfBuilder().sym(spec("target", 0x1100, 16, 1, 2)).build();
        wrongArchitecture[18] = 3;
        assertInvalidElf("architecture.so", wrongArchitecture);

        byte[] valid = new ElfBuilder().sym(spec("target", 0x1100, 16, 1, 2)).build();
        assertInvalidElf("truncated.so", Arrays.copyOf(valid, valid.length - 1));

        byte[] badLink = valid.clone();
        put32(badLink, 0x500 + 2 * 64 + 40, 0);
        assertInvalidElf("link.so", badLink);

        byte[] unterminated = valid.clone();
        Arrays.fill(unterminated, 0x300, 0x380, (byte) 0x41);
        assertInvalidElf("string.so", unterminated);

        byte[] overflow = valid.clone();
        put64(overflow, 40, Long.MAX_VALUE);
        assertInvalidElf("overflow.so", overflow);
    }

    @Test
    void validatesLoadBiasWithGuardAndNonzeroInitialOffsets() throws Exception {
        ElfBuilder builder = new ElfBuilder().sym(spec("target", 0x1100, 16, 1, 2));
        File file = write("mapped.so", builder.build());
        String path = file.getAbsolutePath();
        List<NativeImage.Mapping> mappings = new ArrayList<NativeImage.Mapping>();
        mappings.add(new NativeImage.Mapping(0x60000000L, 0x60000100L, 0x100,
                false, false, path));
        mappings.add(new NativeImage.Mapping(0x70001100L, 0x70001200L, 0x100,
                true, true, path));
        NativeImage image = NativeImage.fromMappings(file, mappings);
        assertEquals(0x70001100L, image.address(image.findSymbol("target")));
        assertArrayEquals(builder.text, image.readPatch(image.findSymbol("target"), 16));
        image.close();
    }

    @Test
    void resolvesSharedFilePagesOnlyWhenGlobalLoadBiasIsUnique() throws Exception {
        ElfBuilder builder = new ElfBuilder().sym(spec("target", 0x1100, 16, 1, 2));
        byte[] bytes = builder.build();
        put16(bytes, 56, 3);
        programHeader(bytes, 1, 4, 0, 0x2000, 0x180);
        programHeader(bytes, 2, 6, 0x180, 0x3180, 0x80);
        File file = write("shared-pages.so", bytes);
        String path = file.getAbsolutePath();
        NativeImage.Mapping executable = new NativeImage.Mapping(
                0x70001100L, 0x70001200L, 0x100, true, true, path);
        NativeImage.Mapping shared = new NativeImage.Mapping(
                0x70003100L, 0x70003200L, 0x100, true, false, path);

        NativeImage image = NativeImage.fromMappings(file, Arrays.asList(executable, shared));
        assertEquals(0x70001100L, image.address(image.findSymbol("target")));
        image.close();
        assertThrows(UnsupportedOperationException.class,
                () -> NativeImage.fromMappings(file, Arrays.asList(shared)));
    }

    @Test
    void rejectsInconsistentNonExecutableAndSplitMappings() throws Exception {
        ElfBuilder builder = new ElfBuilder().sym(spec("target", 0x1100, 16, 1, 2));
        File file = write("bad-mappings.so", builder.build());
        String path = file.getAbsolutePath();
        assertThrows(UnsupportedOperationException.class, () -> NativeImage.fromMappings(file, Arrays.asList(
                new NativeImage.Mapping(0x70001100L, 0x70001200L, 0x100, true, true, path),
                new NativeImage.Mapping(0x70002100L, 0x70002200L, 0x100, true, true, path))));
        assertThrows(UnsupportedOperationException.class, () -> NativeImage.fromMappings(file, Arrays.asList(
                new NativeImage.Mapping(0x70001100L, 0x70001200L, 0x100, true, false, path))));

        NativeImage split = NativeImage.fromMappings(file, Arrays.asList(
                new NativeImage.Mapping(0x70001100L, 0x70001108L, 0x100, true, true, path)));
        assertThrows(UnsupportedOperationException.class,
                () -> split.readPatch(split.findSymbol("target"), 16));
        split.close();
    }

    @Test
    void resolvesExactFdeStartsWithTheirDeclaredRanges() throws Exception {
        FrameBuilder frames = new FrameBuilder();
        int cie = frames.cie(3, "zR", 0x00);
        frames.fde(cie, 0x00, 0x1100, 4);
        frames.fde(cie, 0x00, 0x1110, 8);
        ElfBuilder builder = new ElfBuilder().ehFrame(frames.build());
        Elf64File file = open("fde-ranges.so", builder.build());
        try {
            Elf64File.Symbol first = file.functionAt(0x1100);
            assertEquals(0x1100, first.value);
            assertEquals(4, first.size);
            assertEquals(6, first.section);
            assertEquals(2, first.type);
            assertArrayEquals(Arrays.copyOf(builder.text, 4), file.readFunction(first));
            assertNull(file.functionAt(0x1102));
            assertEquals(8, file.functionAt(0x1110).size);
        } finally {
            file.close();
        }
    }

    @Test
    void supportsCieVersionsAndAllFdeValueFormats() throws Exception {
        int[] encodings = {0x00, 0x01, 0x02, 0x03, 0x04, 0x09, 0x0a, 0x0b, 0x0c};
        int[] versions = {1, 3, 4};
        for (int i = 0; i < encodings.length; i++) {
            FrameBuilder frames = new FrameBuilder();
            String augmentation = i == 0 ? "z" : "zR";
            int encoding = encodings[i];
            int cie = frames.cie(versions[i % versions.length], augmentation, encoding);
            frames.fde(cie, encoding, 0x1100, 16);
            Elf64File file = open("fde-format-" + i + ".so",
                    new ElfBuilder().ehFrame(frames.build()).build());
            try {
                Elf64File.Symbol symbol = file.functionAt(0x1100);
                assertEquals(16, symbol.size);
            } finally {
                file.close();
            }
        }

        FrameBuilder plain = new FrameBuilder();
        int cie = plain.cie(3, "", 0x00);
        plain.fde(cie, 0x00, 0x1100, 16);
        Elf64File file = open("fde-no-augmentation.so",
                new ElfBuilder().ehFrame(plain.build()).build());
        try {
            assertEquals(16, file.functionAt(0x1100).size);
        } finally {
            file.close();
        }
    }

    @Test
    void supportsPcRelativeAndIndirectPersonalityAugmentation() throws Exception {
        int[] encodings = {0x1b, 0x13};
        long[] addresses = {0x1100, 0x1500};
        for (int i = 0; i < encodings.length; i++) {
            FrameBuilder frames = new FrameBuilder();
            int cie = frames.cie(3, "zR", encodings[i]);
            frames.fde(cie, encodings[i], addresses[i], 16);
            Elf64File file = open("fde-relative-" + i + ".so",
                    new ElfBuilder().ehFrame(frames.build()).build());
            try {
                assertEquals(16, file.functionAt(addresses[i]).size);
            } finally {
                file.close();
            }
        }

        FrameBuilder frames = new FrameBuilder();
        int cie = frames.cie(4, "zPLR", 0x1b, 0x9b);
        frames.fde(cie, 0x1b, 0x1100, 16);
        Elf64File file = open("fde-zplr.so", new ElfBuilder().ehFrame(frames.build()).build());
        try {
            assertEquals(16, file.functionAt(0x1100).size);
        } finally {
            file.close();
        }
    }

    @Test
    void acceptsIdenticalDuplicateFdesAndRejectsConflicts() throws Exception {
        FrameBuilder duplicates = new FrameBuilder();
        int cie = duplicates.cie(3, "zR", 0x00);
        duplicates.fde(cie, 0x00, 0x1100, 16);
        duplicates.fde(cie, 0x00, 0x1100, 16);
        Elf64File file = open("fde-duplicates.so",
                new ElfBuilder().ehFrame(duplicates.build()).build());
        try {
            assertEquals(16, file.functionAt(0x1100).size);
        } finally {
            file.close();
        }

        FrameBuilder conflicts = new FrameBuilder();
        cie = conflicts.cie(3, "zR", 0x00);
        conflicts.fde(cie, 0x00, 0x1100, 16);
        conflicts.fde(cie, 0x00, 0x1100, 8);
        assertInvalidFunction("fde-conflict.so", new ElfBuilder().ehFrame(conflicts.build()).build());
    }

    @Test
    void rejectsMissingAmbiguousAndInvalidEhFrameSections() throws Exception {
        assertInvalidFunction("fde-missing.so", new ElfBuilder().build());

        FrameBuilder frames = new FrameBuilder();
        int cie = frames.cie(3, "zR", 0x00);
        frames.fde(cie, 0x00, 0x1100, 16);
        byte[] frame = frames.build();
        assertInvalidFunction("fde-ambiguous.so",
                new ElfBuilder().ehFrame(frame).ehFrame(frame).build());

        byte[] wrongType = new ElfBuilder().ehFrame(frame).build();
        put32(wrongType, 0x500 + 6 * 64 + 4, 8);
        assertInvalidFunction("fde-wrong-type.so", wrongType);

        byte[] badNameIndex = new ElfBuilder().ehFrame(frame).build();
        put16(badNameIndex, 62, 99);
        assertInvalidFunction("fde-name-index.so", badNameIndex);

        byte[] badNameOffset = new ElfBuilder().ehFrame(frame).build();
        put32(badNameOffset, 0x500 + 6 * 64, 0x7fff);
        assertInvalidFunction("fde-name-offset.so", badNameOffset);
    }

    @Test
    void rejectsMalformedEntriesCiePointersAndUnsupportedEncodings() throws Exception {
        FrameBuilder valid = new FrameBuilder();
        int cie = valid.cie(3, "zR", 0x00);
        valid.fde(cie, 0x00, 0x1100, 16);

        byte[] badVersion = valid.build();
        badVersion[valid.lastCieStart + 8] = 2;
        assertInvalidFunction("fde-cie-version.so", new ElfBuilder().ehFrame(badVersion).build());

        byte[] badPointer = valid.build();
        put32(badPointer, valid.lastFdePointerOffset, 1);
        assertInvalidFunction("fde-cie-pointer.so", new ElfBuilder().ehFrame(badPointer).build());

        byte[] truncated = valid.build();
        put32(truncated, valid.lastFdeStart, 0x7fff);
        assertInvalidFunction("fde-truncated.so", new ElfBuilder().ehFrame(truncated).build());

        byte[] badAugmentation = valid.build();
        badAugmentation[valid.lastCieAugmentationLengthOffset] = 0;
        assertInvalidFunction("fde-cie-augmentation.so",
                new ElfBuilder().ehFrame(badAugmentation).build());

        int[] unsupported = {0x80, 0x40, 0x30, 0x20, 0x50, 0x0f, 0xff};
        for (int i = 0; i < unsupported.length; i++) {
            byte[] bytes = valid.build();
            bytes[valid.lastCieEncodingOffset] = (byte) unsupported[i];
            assertInvalidFunction("fde-encoding-" + i + ".so", new ElfBuilder().ehFrame(bytes).build());
        }
    }

    @Test
    void rejectsInvalidFdeRangesOverflowAndBadAugmentationData() throws Exception {
        FrameBuilder outside = new FrameBuilder();
        int cie = outside.cie(3, "zR", 0x00);
        outside.fde(cie, 0x00, 0x9000, 16);
        assertInvalidFunction("fde-outside.so", new ElfBuilder().ehFrame(outside.build()).build());

        FrameBuilder zero = new FrameBuilder();
        cie = zero.cie(3, "zR", 0x00);
        zero.fde(cie, 0x00, 0x1100, 0);
        assertInvalidFunction("fde-zero-range.so", new ElfBuilder().ehFrame(zero.build()).build());

        FrameBuilder overflow = new FrameBuilder();
        cie = overflow.cie(3, "zR", 0x00);
        overflow.fde(cie, 0x00, Long.MAX_VALUE, 16);
        assertInvalidFunction("fde-overflow.so", new ElfBuilder().ehFrame(overflow.build()).build());

        FrameBuilder nonExecutable = new FrameBuilder();
        cie = nonExecutable.cie(3, "zR", 0x00);
        nonExecutable.fde(cie, 0x00, 0x1100, 16);
        byte[] bytes = new ElfBuilder().ehFrame(nonExecutable.build()).build();
        put32(bytes, 68, 4);
        assertInvalidFunction("fde-non-executable.so", bytes);

        FrameBuilder zplr = new FrameBuilder();
        cie = zplr.cie(4, "zPLR", 0x1b);
        zplr.fde(cie, 0x1b, 0x1100, 16);
        byte[] badLsda = zplr.build();
        badLsda[zplr.lastFdeAugmentationLengthOffset] = 0;
        assertInvalidFunction("fde-lsda-length.so", new ElfBuilder().ehFrame(badLsda).build());

        byte[] datarelLsda = zplr.build();
        datarelLsda[zplr.lastCieLsdaEncodingOffset] = 0x3b;
        assertInvalidFunction("fde-lsda-datarel.so", new ElfBuilder().ehFrame(datarelLsda).build());
    }

    private void assertInvalidFunction(String name, byte[] bytes) {
        assertThrows(UnsupportedOperationException.class, () -> {
            Elf64File file = open(name, bytes);
            try {
                file.functionAt(0x1100);
            } finally {
                file.close();
            }
        });
    }

    private void assertInvalidSymbol(String name, Spec spec) throws Exception {
        Elf64File file = open(name, new ElfBuilder().sym(spec).build());
        assertThrows(UnsupportedOperationException.class, () -> file.findSymbol("target"));
        file.close();
    }

    private void assertInvalidElf(String name, byte[] bytes) throws Exception {
        assertThrows(UnsupportedOperationException.class, () -> {
            Elf64File file = open(name, bytes);
            try {
                file.findSymbol("target");
            } finally {
                file.close();
            }
        });
    }

    private Elf64File open(String name, byte[] bytes) throws Exception {
        return new Elf64File(write(name, bytes));
    }

    private File write(String name, byte[] bytes) throws Exception {
        Path path = directory.resolve(name);
        Files.write(path, bytes);
        return path.toFile();
    }

    private static Spec spec(String name, long value, long size, int section, int type) {
        return new Spec(name, value, size, section, type);
    }

    private static void put16(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) value;
        bytes[offset + 1] = (byte) (value >>> 8);
    }

    private static void put32(byte[] bytes, int offset, long value) {
        put16(bytes, offset, (int) value);
        put16(bytes, offset + 2, (int) (value >>> 16));
    }

    private static void put64(byte[] bytes, int offset, long value) {
        put32(bytes, offset, value);
        put32(bytes, offset + 4, value >>> 32);
    }

    private static void programHeader(byte[] bytes, int index, int flags, long fileOffset,
                                      long virtualAddress, long fileSize) {
        int header = 64 + index * 56;
        put32(bytes, header, 1);
        put32(bytes, header + 4, flags);
        put64(bytes, header + 8, fileOffset);
        put64(bytes, header + 16, virtualAddress);
        put64(bytes, header + 24, virtualAddress);
        put64(bytes, header + 32, fileSize);
        put64(bytes, header + 40, fileSize);
        put64(bytes, header + 48, 0x1000);
    }

    private static final class FrameBuilder {
        private final Buffer output = new Buffer();
        private boolean hasAugmentation;
        private int lsdaEncoding;
        private int lastCieStart;
        private int lastCieEncodingOffset;
        private int lastCieLsdaEncodingOffset;
        private int lastCieAugmentationLengthOffset;
        private int lastFdeStart;
        private int lastFdePointerOffset;
        private int lastFdeAugmentationLengthOffset;

        private int cie(int version, String augmentation, int fdeEncoding) {
            return cie(version, augmentation, fdeEncoding, 0x03);
        }

        private int cie(int version, String augmentation, int fdeEncoding,
                        int personalityEncoding) {
            int start = output.size();
            lastCieStart = start;
            write32(output, 0);
            write32(output, 0);
            write8(output, version);
            for (int i = 0; i < augmentation.length(); i++) {
                write8(output, augmentation.charAt(i));
            }
            write8(output, 0);
            if (version == 4) {
                write8(output, 8);
                write8(output, 0);
            }
            uleb(output, 1);
            sleb(output, -8);
            if (version == 1) {
                write8(output, 16);
            } else {
                uleb(output, 16);
            }
            hasAugmentation = augmentation.length() != 0;
            lsdaEncoding = 0xff;
            lastCieEncodingOffset = -1;
            lastCieLsdaEncodingOffset = -1;
            if (hasAugmentation) {
                Buffer data = new Buffer();
                int encodingOffset = -1;
                int lsdaOffset = -1;
                for (int i = 1; i < augmentation.length(); i++) {
                    char code = augmentation.charAt(i);
                    if (code == 'P') {
                        write8(data, personalityEncoding);
                        write32(data, 0);
                    } else if (code == 'L') {
                        lsdaEncoding = 0x0b;
                        lsdaOffset = data.size();
                        write8(data, lsdaEncoding);
                    } else if (code == 'R') {
                        encodingOffset = data.size();
                        write8(data, fdeEncoding);
                    }
                }
                lastCieAugmentationLengthOffset = output.size();
                uleb(output, data.size());
                int dataStart = output.size();
                if (encodingOffset >= 0) {
                    lastCieEncodingOffset = dataStart + encodingOffset;
                }
                if (lsdaOffset >= 0) {
                    lastCieLsdaEncodingOffset = dataStart + lsdaOffset;
                }
                byte[] bytes = data.bytes();
                output.write(bytes, 0, bytes.length);
            }
            output.patch32(start, output.size() - start - 4);
            return start;
        }

        private void fde(int cieOffset, int encoding, long begin, long range) {
            int start = output.size();
            lastFdeStart = start;
            write32(output, 0);
            lastFdePointerOffset = output.size();
            write32(output, start + 4 - cieOffset);
            int initialLocation = output.size();
            long base = (encoding & 0x70) == 0x10 ? 0x1400 + initialLocation
                    : (encoding & 0x70) == 0x30 ? 0x1400 : 0;
            encoded(output, encoding, begin - base);
            encoded(output, encoding & 0x0f, range);
            if (hasAugmentation) {
                lastFdeAugmentationLengthOffset = output.size();
                if (lsdaEncoding == 0xff) {
                    uleb(output, 0);
                } else {
                    uleb(output, 4);
                    write32(output, 0);
                }
            }
            output.patch32(start, output.size() - start - 4);
        }

        private byte[] build() {
            return Arrays.copyOf(output.bytes(), output.size() + 4);
        }

        private static void encoded(Buffer output, int encoding, long value) {
            switch (encoding & 0x0f) {
                case 0x00:
                case 0x04:
                case 0x0c:
                    write64(output, value);
                    return;
                case 0x01:
                    uleb(output, value);
                    return;
                case 0x02:
                case 0x0a:
                    write16(output, (int) value);
                    return;
                case 0x03:
                case 0x0b:
                    write32(output, value);
                    return;
                case 0x09:
                    sleb(output, value);
                    return;
                default:
                    throw new IllegalArgumentException("Unsupported test encoding");
            }
        }

        private static void uleb(Buffer output, long value) {
            if (value < 0) {
                throw new IllegalArgumentException("Negative ULEB128 test value");
            }
            do {
                int next = (int) (value & 0x7f);
                value >>>= 7;
                if (value != 0) {
                    next |= 0x80;
                }
                write8(output, next);
            } while (value != 0);
        }

        private static void sleb(Buffer output, long value) {
            boolean more;
            do {
                int next = (int) (value & 0x7f);
                value >>= 7;
                more = !(value == 0 && (next & 0x40) == 0 || value == -1 && (next & 0x40) != 0);
                if (more) {
                    next |= 0x80;
                }
                write8(output, next);
            } while (more);
        }

        private static void write8(Buffer output, int value) {
            output.write(value);
        }

        private static void write16(Buffer output, int value) {
            write8(output, value);
            write8(output, value >>> 8);
        }

        private static void write32(Buffer output, long value) {
            write16(output, (int) value);
            write16(output, (int) (value >>> 16));
        }

        private static void write64(Buffer output, long value) {
            write32(output, value);
            write32(output, value >>> 32);
        }
    }

    private static final class Buffer extends ByteArrayOutputStream {
        private void patch32(int offset, long value) {
            put32(buf, offset, value);
        }

        private byte[] bytes() {
            return Arrays.copyOf(buf, count);
        }
    }

    private static final class Spec {
        private final String name;
        private final long value;
        private final long size;
        private final int section;
        private final int type;

        private Spec(String name, long value, long size, int section, int type) {
            this.name = name;
            this.value = value;
            this.size = size;
            this.section = section;
            this.type = type;
        }
    }

    private static final class ElfBuilder {
        private final List<Spec> symtab = new ArrayList<Spec>();
        private final List<Spec> dynsym = new ArrayList<Spec>();
        private final List<byte[]> ehFrames = new ArrayList<byte[]>();
        private final byte[] text = new byte[]{0x55, (byte) 0x48, (byte) 0x89, (byte) 0xe5,
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, (byte) 0xc3};

        private ElfBuilder sym(Spec spec) {
            symtab.add(spec);
            return this;
        }

        private ElfBuilder dyn(Spec spec) {
            dynsym.add(spec);
            return this;
        }

        private ElfBuilder ehFrame(byte[] bytes) {
            if (bytes.length > 0x80) {
                throw new IllegalArgumentException("Oversized synthetic .eh_frame section");
            }
            ehFrames.add(bytes);
            return this;
        }

        private byte[] build() {
            int extraSections = ehFrames.isEmpty() ? 0 : ehFrames.size() + 1;
            byte[] bytes = new byte[0x680 + extraSections * 64];
            bytes[0] = 0x7f;
            bytes[1] = 'E';
            bytes[2] = 'L';
            bytes[3] = 'F';
            bytes[4] = 2;
            bytes[5] = 1;
            bytes[6] = 1;
            put16(bytes, 16, 3);
            put16(bytes, 18, 62);
            put32(bytes, 20, 1);
            put64(bytes, 32, 64);
            put64(bytes, 40, 0x500);
            put16(bytes, 52, 64);
            put16(bytes, 54, 56);
            put16(bytes, 56, 1);
            put16(bytes, 58, 64);
            put16(bytes, 60, 6 + extraSections);
            put32(bytes, 64, 1);
            put32(bytes, 68, 5);
            put64(bytes, 72, 0);
            put64(bytes, 80, 0x1000);
            put64(bytes, 96, bytes.length);
            put64(bytes, 104, bytes.length);
            put64(bytes, 112, 0x1000);
            System.arraycopy(text, 0, bytes, 0x100, text.length);
            byte[] strings = strings(symtab);
            byte[] dynStrings = strings(dynsym);
            System.arraycopy(strings, 0, bytes, 0x300, strings.length);
            System.arraycopy(dynStrings, 0, bytes, 0x380, dynStrings.length);
            symbols(bytes, 0x180, symtab, strings);
            symbols(bytes, 0x280, dynsym, dynStrings);
            section(bytes, 1, 1, 0x100, text.length, 0, 0);
            section(bytes, 2, 2, 0x180, (symtab.size() + 1) * 24, 3, 24);
            section(bytes, 3, 3, 0x300, strings.length, 0, 0);
            section(bytes, 4, 11, 0x280, (dynsym.size() + 1) * 24, 5, 24);
            section(bytes, 5, 3, 0x380, dynStrings.length, 0, 0);
            if (!ehFrames.isEmpty()) {
                byte[] sectionNames = new byte[0x80];
                byte[] ehFrameName = ".eh_frame".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                byte[] shstrName = ".shstrtab".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                System.arraycopy(ehFrameName, 0, sectionNames, 1, ehFrameName.length);
                System.arraycopy(shstrName, 0, sectionNames, 11, shstrName.length);
                System.arraycopy(sectionNames, 0, bytes, 0x480, sectionNames.length);
                for (int i = 0; i < ehFrames.size(); i++) {
                    byte[] frame = ehFrames.get(i);
                    System.arraycopy(frame, 0, bytes, 0x400, frame.length);
                    section(bytes, 6 + i, 1, 0x400, frame.length, 0, 0);
                    int header = 0x500 + (6 + i) * 64;
                    put32(bytes, header, 1);
                    put64(bytes, header + 16, 0x1400);
                }
                int shstrIndex = 6 + ehFrames.size();
                section(bytes, shstrIndex, 3, 0x480, sectionNames.length, 0, 0);
                put32(bytes, 0x500 + shstrIndex * 64, 11);
                put16(bytes, 62, shstrIndex);
            }
            put64(bytes, 0x500 + 64 + 16, 0x1100);
            return bytes;
        }

        private static byte[] strings(List<Spec> specs) {
            byte[] result = new byte[128];
            int offset = 1;
            for (Spec spec : specs) {
                byte[] name = spec.name.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                System.arraycopy(name, 0, result, offset, name.length);
                offset += name.length + 1;
            }
            return result;
        }

        private static void symbols(byte[] bytes, int tableOffset, List<Spec> specs, byte[] strings) {
            int stringOffset = 1;
            for (int i = 0; i < specs.size(); i++) {
                Spec spec = specs.get(i);
                int offset = tableOffset + (i + 1) * 24;
                put32(bytes, offset, stringOffset);
                bytes[offset + 4] = (byte) (0x10 | spec.type);
                put16(bytes, offset + 6, spec.section);
                put64(bytes, offset + 8, spec.value);
                put64(bytes, offset + 16, spec.size);
                stringOffset += spec.name.getBytes(java.nio.charset.StandardCharsets.UTF_8).length + 1;
            }
        }

        private static void section(byte[] bytes, int index, int type, long offset, long size,
                                    int link, int entrySize) {
            int header = 0x500 + index * 64;
            put32(bytes, header + 4, type);
            put64(bytes, header + 24, offset);
            put64(bytes, header + 32, size);
            put32(bytes, header + 40, link);
            put64(bytes, header + 56, entrySize);
        }
    }
}
