package com.reajason.javaweb.fileless;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Minimal, bounded ELF64 reader for mapped Linux/x86-64 and AArch64 shared objects. */
final class Elf64File {
    private static final int EM_X86_64 = 62;
    private static final int EM_AARCH64 = 183;
    private static final int ELF_HEADER_SIZE = 64;
    private static final int PROGRAM_HEADER_SIZE = 56;
    private static final int SECTION_HEADER_SIZE = 64;
    private static final int SYMBOL_SIZE = 24;
    private static final int MAX_PROGRAM_HEADERS = 4096;
    private static final int MAX_SECTION_HEADERS = 65535;
    private static final int MAX_STRING_TABLE_SIZE = 64 * 1024 * 1024;
    private static final int MAX_FUNCTION_SIZE = 1024 * 1024;
    private static final int MAX_EH_FRAME_SIZE = 64 * 1024 * 1024;
    private static final int MAX_EH_FRAME_ENTRIES = 1000000;
    private static final int PT_LOAD = 1;
    private static final int PF_X = 1;
    private static final int SHT_PROGBITS = 1;
    private static final int SHT_SYMTAB = 2;
    private static final int SHT_STRTAB = 3;
    private static final int SHT_NOBITS = 8;
    private static final int SHT_DYNSYM = 11;
    private static final int STT_FUNC = 2;
    private static final int STT_GNU_IFUNC = 10;
    private static final int DW_EH_PE_OMIT = 0xff;
    private static final int DW_EH_PE_INDIRECT = 0x80;
    private static final int DW_EH_PE_ABSPTR = 0x00;
    private static final int DW_EH_PE_ULEB128 = 0x01;
    private static final int DW_EH_PE_UDATA2 = 0x02;
    private static final int DW_EH_PE_UDATA4 = 0x03;
    private static final int DW_EH_PE_UDATA8 = 0x04;
    private static final int DW_EH_PE_SLEB128 = 0x09;
    private static final int DW_EH_PE_SDATA2 = 0x0a;
    private static final int DW_EH_PE_SDATA4 = 0x0b;
    private static final int DW_EH_PE_SDATA8 = 0x0c;
    private static final int DW_EH_PE_PCREL = 0x10;

    private final RandomAccessFile input;
    private final long fileLength;
    private final Segment[] loadSegments;
    private final Section[] sections;
    private final int sectionNameIndex;
    private int machine;

    Elf64File(File file) throws IOException {
        input = new RandomAccessFile(file, "r");
        boolean success = false;
        try {
            fileLength = input.length();
            if (fileLength < ELF_HEADER_SIZE) {
                throw invalid("Truncated ELF header");
            }
            byte[] header = new byte[ELF_HEADER_SIZE];
            input.seek(0L);
            input.readFully(header);
            validateHeader(header);
            sectionNameIndex = u16(header, 62);
            loadSegments = readLoadSegments(header);
            sections = readSections(header);
            success = true;
        } finally {
            if (!success) {
                input.close();
            }
        }
    }

    private void validateHeader(byte[] header) {
        if ((header[0] & 0xff) != 0x7f || header[1] != 'E' || header[2] != 'L' || header[3] != 'F'
                || header[4] != 2 || header[5] != 1 || header[6] != 1) {
            throw invalid("Expected a little-endian ELF64 image");
        }
        machine = u16(header, 18);
        if (u16(header, 16) != 3 || machine != EM_X86_64 && machine != EM_AARCH64
                || u32(header, 20) != 1L
                || u16(header, 52) != ELF_HEADER_SIZE || u16(header, 54) != PROGRAM_HEADER_SIZE
                || u16(header, 58) != SECTION_HEADER_SIZE) {
            throw invalid("Unsupported ELF64 shared-object header");
        }
        if (u16(header, 56) == 0xffff || u16(header, 62) == 0xffff) {
            throw invalid("Extended ELF numbering is not supported");
        }
    }

    private Segment[] readLoadSegments(byte[] header) throws IOException {
        int count = u16(header, 56);
        int tableOffset = u16(header, 54);
        long offset = i64(header, 32);
        if (count <= 0 || count > MAX_PROGRAM_HEADERS) {
            throw invalid("Invalid ELF program-header count");
        }
        range(offset, (long) count * tableOffset);
        List<Segment> result = new ArrayList<Segment>();
        byte[] bytes = new byte[PROGRAM_HEADER_SIZE];
        for (int i = 0; i < count; i++) {
            input.seek(offset + (long) i * tableOffset);
            input.readFully(bytes);
            int type = (int) u32(bytes, 0);
            if (type != PT_LOAD) {
                continue;
            }
            int flags = (int) u32(bytes, 4);
            long fileOffset = i64(bytes, 8);
            long virtualAddress = i64(bytes, 16);
            long fileSize = i64(bytes, 32);
            long memorySize = i64(bytes, 40);
            long alignment = i64(bytes, 48);
            if (fileSize < 0 || memorySize < fileSize || virtualAddress < 0
                    || virtualAddress + memorySize < virtualAddress
                    || (alignment != 0 && alignment != 1
                    && ((alignment & (alignment - 1)) != 0
                    || (virtualAddress & (alignment - 1)) != (fileOffset & (alignment - 1))))) {
                throw invalid("Invalid ELF PT_LOAD segment");
            }
            range(fileOffset, fileSize);
            result.add(new Segment(fileOffset, virtualAddress, fileSize, memorySize, flags));
        }
        if (result.isEmpty()) {
            throw invalid("ELF image has no PT_LOAD segment");
        }
        return result.toArray(new Segment[result.size()]);
    }

    private Section[] readSections(byte[] header) throws IOException {
        int count = u16(header, 60);
        int entrySize = u16(header, 58);
        long offset = i64(header, 40);
        if (count <= 0 || count > MAX_SECTION_HEADERS) {
            throw invalid("Invalid ELF section-header count");
        }
        range(offset, (long) count * entrySize);
        Section[] result = new Section[count];
        byte[] bytes = new byte[SECTION_HEADER_SIZE];
        for (int i = 0; i < count; i++) {
            input.seek(offset + (long) i * entrySize);
            input.readFully(bytes);
            Section section = new Section(i, (int) u32(bytes, 0), (int) u32(bytes, 4),
                    i64(bytes, 16), i64(bytes, 24), i64(bytes, 32), (int) u32(bytes, 40),
                    i64(bytes, 56));
            if (section.fileOffset < 0 || section.size < 0
                    || (section.type != SHT_NOBITS && section.size != 0)) {
                range(section.fileOffset, section.size);
            }
            result[i] = section;
        }
        return result;
    }

    synchronized Symbol findSymbol(String name) throws IOException {
        if (name == null || name.length() == 0) {
            throw new IllegalArgumentException("Symbol name is required");
        }
        return findSymbols(new String[]{name})[0];
    }

    synchronized Symbol[] findSymbols(String[] names) throws IOException {
        if (names == null || names.length == 0) {
            throw new IllegalArgumentException("Symbol names are required");
        }
        Match[] matches = new Match[names.length];
        for (int i = 0; i < names.length; i++) {
            if (names[i] == null || names[i].length() == 0) {
                throw new IllegalArgumentException("Symbol names are required");
            }
            for (int j = 0; j < i; j++) {
                if (names[i].equals(names[j])) {
                    throw new IllegalArgumentException("Duplicate symbol request: " + names[i]);
                }
            }
        }
        for (int sectionIndex = 0; sectionIndex < sections.length; sectionIndex++) {
            Section table = sections[sectionIndex];
            if (table.type != SHT_SYMTAB && table.type != SHT_DYNSYM) {
                continue;
            }
            if (table.entrySize != SYMBOL_SIZE || table.size % SYMBOL_SIZE != 0
                    || table.link <= 0 || table.link >= sections.length
                    || sections[table.link].type != SHT_STRTAB
                    || sections[table.link].size > MAX_STRING_TABLE_SIZE) {
                throw invalid("Invalid ELF symbol table");
            }
            byte[] strings = readRange(sections[table.link].fileOffset,
                    checkedInt(sections[table.link].size, "String table is too large"));
            long symbolCount = table.size / SYMBOL_SIZE;
            if (symbolCount > Integer.MAX_VALUE) {
                throw invalid("ELF symbol table is too large");
            }
            byte[] buffer = new byte[(int) Math.min(table.size, 8160L)];
            long position = 0;
            while (position < table.size) {
                int length = (int) Math.min(buffer.length, table.size - position);
                input.seek(table.fileOffset + position);
                input.readFully(buffer, 0, length);
                for (int offset = 0; offset < length; offset += SYMBOL_SIZE) {
                    int nameOffset = (int) u32(buffer, offset);
                    String name = string(strings, nameOffset);
                    for (int i = 0; i < names.length; i++) {
                        if (names[i].equals(name)) {
                            Match match = matches[i];
                            if (match == null) {
                                match = new Match();
                                matches[i] = match;
                            }
                            match.add(symbol(buffer, offset));
                        }
                    }
                }
                position += length;
            }
        }
        Symbol[] result = new Symbol[names.length];
        for (int i = 0; i < names.length; i++) {
            if (matches[i] != null) {
                result[i] = matches[i].resolved(names[i]);
            }
        }
        return result;
    }

    synchronized Symbol functionAt(long virtualAddress) throws IOException {
        Section ehFrame = findEhFrameSection();
        if (ehFrame.size > MAX_EH_FRAME_SIZE) {
            throw invalid("ELF .eh_frame section is too large");
        }
        byte[] bytes = readRange(ehFrame.fileOffset,
                checkedInt(ehFrame.size, "ELF .eh_frame section is too large"));
        return parseEhFrame(bytes, ehFrame, virtualAddress);
    }

    private Section findEhFrameSection() throws IOException {
        if (sectionNameIndex == 0) {
            throw invalid("ELF image has no .eh_frame section");
        }
        if (sectionNameIndex >= sections.length
                || sections[sectionNameIndex].type != SHT_STRTAB
                || sections[sectionNameIndex].size > MAX_STRING_TABLE_SIZE) {
            throw invalid("Invalid ELF section-name string table");
        }
        byte[] names = readRange(sections[sectionNameIndex].fileOffset,
                checkedInt(sections[sectionNameIndex].size, "Section-name table is too large"));
        if (names.length == 0 || names[0] != 0) {
            throw invalid("Invalid ELF section-name string table");
        }
        Section result = null;
        for (int i = 0; i < sections.length; i++) {
            String name = string(names, sections[i].nameOffset);
            if (!".eh_frame".equals(name)) {
                continue;
            }
            if (i == 0 || sections[i].type != SHT_PROGBITS) {
                throw invalid("Invalid ELF .eh_frame section");
            }
            if (result != null) {
                throw invalid("Ambiguous ELF .eh_frame sections");
            }
            result = sections[i];
        }
        if (result == null) {
            throw invalid("ELF image has no .eh_frame section");
        }
        return result;
    }

    private Symbol parseEhFrame(byte[] bytes, Section section, long virtualAddress) {
        Map<Long, Cie> cies = new HashMap<Long, Cie>();
        Map<Long, Long> fdes = new HashMap<Long, Long>();
        Cursor input = new Cursor(bytes, 0, bytes.length);
        Symbol result = null;
        int entryCount = 0;
        while (input.remaining() != 0) {
            if (input.remaining() < 4) {
                throw invalid("Truncated ELF .eh_frame entry");
            }
            int entryStart = input.position;
            long initialLength = input.u32();
            if (initialLength == 0) {
                input.requireZeroPadding();
                break;
            }
            long length = initialLength;
            if (initialLength == 0xffffffffL) {
                if (input.remaining() < 8) {
                    throw invalid("Truncated ELF .eh_frame extended length");
                }
                length = input.u64();
                if (length < 0) {
                    throw invalid("ELF .eh_frame entry is too large");
                }
            }
            if (length < 4 || length > input.remaining()) {
                throw invalid("Invalid ELF .eh_frame entry length");
            }
            if (++entryCount > MAX_EH_FRAME_ENTRIES) {
                throw invalid("Too many ELF .eh_frame entries");
            }
            int contentStart = input.position;
            int entryEnd = contentStart + (int) length;
            Cursor entry = new Cursor(bytes, contentStart, entryEnd);
            long ciePointer = entry.u32();
            if (ciePointer == 0) {
                cies.put(Long.valueOf(entryStart), readCie(entry));
            } else {
                Symbol symbol = readFde(entry, section, contentStart, ciePointer, cies,
                        fdes, virtualAddress);
                if (symbol != null) {
                    result = symbol;
                }
            }
            input.position = entryEnd;
        }
        return result;
    }

    private Cie readCie(Cursor entry) {
        int version = entry.u8();
        if (version != 1 && version != 3 && version != 4) {
            throw invalid("Unsupported ELF .eh_frame CIE version");
        }
        String augmentation = entry.augmentation();
        validateAugmentation(augmentation);
        if (version == 4 && (entry.u8() != 8 || entry.u8() != 0)) {
            throw invalid("Unsupported ELF .eh_frame CIE address format");
        }
        if (entry.uleb() <= 0) {
            throw invalid("Invalid ELF .eh_frame code alignment");
        }
        entry.sleb();
        if (version == 1) {
            entry.u8();
        } else {
            entry.uleb();
        }

        Cie cie = new Cie();
        if (augmentation.length() == 0) {
            return cie;
        }
        cie.hasAugmentation = true;
        Cursor data = entry.subCursor(entry.uleb());
        boolean personality = false;
        boolean lsda = false;
        boolean fdeEncoding = false;
        for (int i = 1; i < augmentation.length(); i++) {
            char code = augmentation.charAt(i);
            if (code == 'R') {
                if (fdeEncoding) {
                    throw invalid("Duplicate ELF .eh_frame FDE encoding");
                }
                fdeEncoding = true;
                cie.fdeEncoding = data.u8();
                validateEncoding(cie.fdeEncoding, false);
            } else if (code == 'P') {
                if (personality) {
                    throw invalid("Duplicate ELF .eh_frame personality encoding");
                }
                personality = true;
                int encoding = data.u8();
                skipEncoded(data, encoding);
            } else if (code == 'L') {
                if (lsda) {
                    throw invalid("Duplicate ELF .eh_frame LSDA encoding");
                }
                lsda = true;
                cie.hasLsda = true;
                cie.lsdaEncoding = data.u8();
                validateEncoding(cie.lsdaEncoding, true);
            }
        }
        if (data.remaining() != 0) {
            throw invalid("Invalid ELF .eh_frame CIE augmentation length");
        }
        return cie;
    }

    private Symbol readFde(Cursor entry, Section section, int pointerOffset, long ciePointer,
                           Map<Long, Cie> cies, Map<Long, Long> fdes, long requestedAddress) {
        long cieOffset = pointerOffset - ciePointer;
        Cie cie = cies.get(Long.valueOf(cieOffset));
        if (cie == null) {
            throw invalid("Invalid ELF .eh_frame CIE pointer");
        }
        long begin = readEncoded(entry, cie.fdeEncoding, section);
        long addressRange = readEncoded(entry, cie.fdeEncoding & 0x0f, section);
        if (begin <= 0 || addressRange <= 0) {
            throw invalid("Invalid ELF .eh_frame FDE address range");
        }
        fileOffset(begin, checkedInt(addressRange, "ELF .eh_frame FDE range is too large"), true);
        if (cie.hasAugmentation) {
            Cursor data = entry.subCursor(entry.uleb());
            if (cie.hasLsda && cie.lsdaEncoding != DW_EH_PE_OMIT) {
                readEncoded(data, cie.lsdaEncoding, section);
            }
            if (data.remaining() != 0) {
                throw invalid("Invalid ELF .eh_frame FDE augmentation length");
            }
        }
        Long key = Long.valueOf(begin);
        Long previous = fdes.get(key);
        if (previous != null && previous.longValue() != addressRange) {
            throw invalid("Conflicting ELF .eh_frame FDE definitions");
        }
        fdes.put(key, Long.valueOf(addressRange));
        if (begin == requestedAddress) {
            return new Symbol(begin, addressRange, section.index, STT_FUNC);
        }
        return null;
    }

    private static void validateAugmentation(String augmentation) {
        if (augmentation.length() == 0) {
            return;
        }
        if (augmentation.charAt(0) != 'z') {
            throw invalid("Unsupported ELF .eh_frame CIE augmentation");
        }
        for (int i = 1; i < augmentation.length(); i++) {
            char code = augmentation.charAt(i);
            if (code != 'R' && code != 'P' && code != 'L') {
                throw invalid("Unsupported ELF .eh_frame CIE augmentation");
            }
        }
    }

    private static void validateEncoding(int encoding, boolean allowOmit) {
        if (encoding == DW_EH_PE_OMIT) {
            if (allowOmit) {
                return;
            }
            throw invalid("Omitted ELF .eh_frame encoding");
        }
        int application = encoding & 0x70;
        if ((encoding & DW_EH_PE_INDIRECT) != 0
                || application != 0 && application != DW_EH_PE_PCREL) {
            throw invalid("Unsupported ELF .eh_frame pointer encoding");
        }
        switch (encoding & 0x0f) {
            case DW_EH_PE_ABSPTR:
            case DW_EH_PE_ULEB128:
            case DW_EH_PE_UDATA2:
            case DW_EH_PE_UDATA4:
            case DW_EH_PE_UDATA8:
            case DW_EH_PE_SLEB128:
            case DW_EH_PE_SDATA2:
            case DW_EH_PE_SDATA4:
            case DW_EH_PE_SDATA8:
                return;
            default:
                throw invalid("Unknown ELF .eh_frame pointer encoding");
        }
    }

    private static void skipEncoded(Cursor input, int encoding) {
        if (encoding == DW_EH_PE_OMIT) {
            throw invalid("Omitted ELF .eh_frame personality encoding");
        }
        int application = encoding & 0x70;
        if (application >= 0x50) {
            throw invalid("Unsupported ELF .eh_frame personality encoding");
        }
        switch (encoding & 0x0f) {
            case DW_EH_PE_ABSPTR:
            case DW_EH_PE_UDATA8:
            case DW_EH_PE_SDATA8:
                input.skip(8);
                return;
            case DW_EH_PE_ULEB128:
                input.uleb();
                return;
            case DW_EH_PE_UDATA2:
            case DW_EH_PE_SDATA2:
                input.skip(2);
                return;
            case DW_EH_PE_UDATA4:
            case DW_EH_PE_SDATA4:
                input.skip(4);
                return;
            case DW_EH_PE_SLEB128:
                input.sleb();
                return;
            default:
                throw invalid("Unknown ELF .eh_frame personality encoding");
        }
    }

    private static long readEncoded(Cursor input, int encoding, Section section) {
        validateEncoding(encoding, false);
        int fieldOffset = input.position;
        int application = encoding & 0x70;
        long value;
        boolean signed;
        switch (encoding & 0x0f) {
            case DW_EH_PE_ABSPTR:
            case DW_EH_PE_UDATA8:
                value = input.u64();
                if (value < 0) {
                    throw invalid("ELF .eh_frame address exceeds the supported range");
                }
                signed = false;
                break;
            case DW_EH_PE_ULEB128:
                value = input.uleb();
                signed = false;
                break;
            case DW_EH_PE_UDATA2:
                value = input.u16();
                signed = false;
                break;
            case DW_EH_PE_UDATA4:
                value = input.u32();
                signed = false;
                break;
            case DW_EH_PE_SLEB128:
                value = input.sleb();
                signed = true;
                break;
            case DW_EH_PE_SDATA2:
                value = (short) input.u16();
                signed = true;
                break;
            case DW_EH_PE_SDATA4:
                value = (int) input.u32();
                signed = true;
                break;
            case DW_EH_PE_SDATA8:
                value = input.u64();
                signed = true;
                break;
            default:
                throw new AssertionError();
        }
        if (application == 0) {
            if (value < 0) {
                throw invalid("Negative ELF .eh_frame address");
            }
            return value;
        }
        long base = 0;
        if (application == DW_EH_PE_PCREL) {
            base = addAddress(section.address, fieldOffset, false);
        }
        return addAddress(base, value, signed);
    }

    private static long addAddress(long base, long value, boolean signed) {
        if (!signed) {
            if (base < 0 || value < 0 || base > Long.MAX_VALUE - value) {
                throw invalid("ELF .eh_frame address overflow");
            }
            return base + value;
        }
        long result = base + value;
        if (((base ^ result) & (value ^ result)) < 0 || result < 0) {
            throw invalid("ELF .eh_frame address overflow");
        }
        return result;
    }

    private Symbol symbol(byte[] bytes, int offset) {
        int info = bytes[offset + 4] & 0xff;
        int section = u16(bytes, offset + 6);
        return new Symbol(i64(bytes, offset + 8), i64(bytes, offset + 16), section,
                info & 0x0f);
    }

    private static String string(byte[] strings, int offset) {
        if (offset < 0 || offset >= strings.length) {
            throw invalid("ELF symbol name is outside its string table");
        }
        int end = offset;
        while (end < strings.length && strings[end] != 0 && end - offset <= 4096) {
            end++;
        }
        if (end >= strings.length || strings[end] != 0 || end - offset > 4096) {
            throw invalid("Unterminated or oversized ELF symbol name");
        }
        try {
            return new String(strings, offset, end - offset, "UTF-8");
        } catch (java.io.UnsupportedEncodingException impossible) {
            throw new AssertionError(impossible);
        }
    }

    synchronized byte[] readFunction(Symbol symbol) throws IOException {
        requireSymbol(symbol);
        if (symbol.size <= 0 || symbol.size > MAX_FUNCTION_SIZE) {
            throw invalid("Invalid native function size");
        }
        return read(symbol, 0L, (int) symbol.size);
    }

    synchronized byte[] read(Symbol symbol, long offset, int length) throws IOException {
        requireSymbol(symbol);
        if (offset < 0 || length < 0 || offset + length < offset || offset + length > symbol.size) {
            throw invalid("Native read is outside the resolved function");
        }
        long fileOffset = fileOffset(symbol.value + offset, length, true);
        return readRange(fileOffset, length);
    }

    long fileOffset(long virtualAddress, int length, boolean executable) {
        if (virtualAddress < 0 || length < 0 || virtualAddress + length < virtualAddress) {
            throw invalid("Invalid ELF virtual-address range");
        }
        long result = -1L;
        for (int i = 0; i < loadSegments.length; i++) {
            Segment segment = loadSegments[i];
            if (executable && (segment.flags & PF_X) == 0) {
                continue;
            }
            if (virtualAddress >= segment.virtualAddress
                    && virtualAddress + length <= segment.virtualAddress + segment.fileSize) {
                if (result != -1L) {
                    throw invalid("Ambiguous ELF PT_LOAD mapping");
                }
                result = segment.fileOffset + virtualAddress - segment.virtualAddress;
            }
        }
        if (result == -1L) {
            throw invalid("Address is not in a file-backed executable PT_LOAD segment");
        }
        return result;
    }

    boolean isAarch64() {
        return machine == EM_AARCH64;
    }

    Segment[] getLoadSegments() {
        return loadSegments.clone();
    }

    synchronized void close() throws IOException {
        input.close();
    }

    private byte[] readRange(long offset, int length) throws IOException {
        range(offset, length);
        byte[] result = new byte[length];
        input.seek(offset);
        input.readFully(result);
        return result;
    }

    private void range(long offset, long size) {
        if (offset < 0 || size < 0 || offset > fileLength || size > fileLength - offset) {
            throw invalid("ELF table range is outside the file");
        }
    }

    private static void requireSymbol(Symbol symbol) {
        if (symbol == null || symbol.type != STT_FUNC || symbol.section == 0 || symbol.value <= 0) {
            throw invalid("A defined function symbol is required");
        }
    }

    private static int checkedInt(long value, String message) {
        if (value < 0 || value > Integer.MAX_VALUE) {
            throw invalid(message);
        }
        return (int) value;
    }

    private static int u16(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
    }

    private static long u32(byte[] bytes, int offset) {
        return (long) u16(bytes, offset) | ((long) u16(bytes, offset + 2) << 16);
    }

    private static long i64(byte[] bytes, int offset) {
        long value = u32(bytes, offset) | (u32(bytes, offset + 4) << 32);
        if (value < 0) {
            throw invalid("ELF value exceeds the supported positive range");
        }
        return value;
    }

    private static UnsupportedOperationException invalid(String message) {
        return new UnsupportedOperationException(message + "; native state was not changed");
    }

    static final class Symbol {
        final long value;
        final long size;
        final int section;
        final int type;

        Symbol(long value, long size, int section, int type) {
            this.value = value;
            this.size = size;
            this.section = section;
            this.type = type;
        }
    }

    static final class Segment {
        final long fileOffset;
        final long virtualAddress;
        final long fileSize;
        final long memorySize;
        final int flags;

        Segment(long fileOffset, long virtualAddress, long fileSize, long memorySize, int flags) {
            this.fileOffset = fileOffset;
            this.virtualAddress = virtualAddress;
            this.fileSize = fileSize;
            this.memorySize = memorySize;
            this.flags = flags;
        }
    }

    private static final class Section {
        private final int index;
        private final int nameOffset;
        private final int type;
        private final long address;
        private final long fileOffset;
        private final long size;
        private final int link;
        private final long entrySize;

        private Section(int index, int nameOffset, int type, long address, long fileOffset,
                        long size, int link, long entrySize) {
            this.index = index;
            this.nameOffset = nameOffset;
            this.type = type;
            this.address = address;
            this.fileOffset = fileOffset;
            this.size = size;
            this.link = link;
            this.entrySize = entrySize;
        }
    }

    private static final class Cie {
        private boolean hasAugmentation;
        private boolean hasLsda;
        private int lsdaEncoding = DW_EH_PE_OMIT;
        private int fdeEncoding = DW_EH_PE_ABSPTR;
    }

    private static final class Cursor {
        private final byte[] bytes;
        private final int limit;
        private int position;

        private Cursor(byte[] bytes, int position, int limit) {
            this.bytes = bytes;
            this.position = position;
            this.limit = limit;
        }

        private int remaining() {
            return limit - position;
        }

        private int u8() {
            require(1);
            return bytes[position++] & 0xff;
        }

        private int u16() {
            require(2);
            int result = Elf64File.u16(bytes, position);
            position += 2;
            return result;
        }

        private long u32() {
            require(4);
            long result = Elf64File.u32(bytes, position);
            position += 4;
            return result;
        }

        private long u64() {
            require(8);
            long result = Elf64File.u32(bytes, position) | (Elf64File.u32(bytes, position + 4) << 32);
            position += 8;
            return result;
        }

        private long uleb() {
            long result = 0;
            for (int i = 0; i < 10; i++) {
                int next = u8();
                int payload = next & 0x7f;
                if (i == 9 && (payload > 1 || (next & 0x80) != 0)) {
                    throw invalid("Overflowing ELF .eh_frame ULEB128 value");
                }
                result |= (long) payload << (i * 7);
                if ((next & 0x80) == 0) {
                    if (result < 0) {
                        throw invalid("ELF .eh_frame ULEB128 value exceeds the supported range");
                    }
                    return result;
                }
            }
            throw new AssertionError();
        }

        private long sleb() {
            long result = 0;
            for (int i = 0; i < 10; i++) {
                int next = u8();
                int payload = next & 0x7f;
                if (i == 9 && (payload != 0 && payload != 0x7f || (next & 0x80) != 0)) {
                    throw invalid("Overflowing ELF .eh_frame SLEB128 value");
                }
                result |= (long) payload << (i * 7);
                if ((next & 0x80) == 0) {
                    int shift = (i + 1) * 7;
                    if (shift < 64 && (next & 0x40) != 0) {
                        result |= -1L << shift;
                    }
                    return result;
                }
            }
            throw new AssertionError();
        }

        private String augmentation() {
            int start = position;
            while (position < limit && bytes[position] != 0) {
                position++;
                if (position - start > 64) {
                    throw invalid("Oversized ELF .eh_frame augmentation string");
                }
            }
            if (position == limit) {
                throw invalid("Unterminated ELF .eh_frame augmentation string");
            }
            char[] result = new char[position - start];
            for (int i = 0; i < result.length; i++) {
                result[i] = (char) (bytes[start + i] & 0xff);
            }
            position++;
            return new String(result);
        }

        private Cursor subCursor(long length) {
            if (length < 0 || length > remaining()) {
                throw invalid("Invalid ELF .eh_frame augmentation data length");
            }
            Cursor result = new Cursor(bytes, position, position + (int) length);
            position += (int) length;
            return result;
        }

        private void requireZeroPadding() {
            while (position < limit) {
                if (bytes[position++] != 0) {
                    throw invalid("Data follows the ELF .eh_frame terminator");
                }
            }
        }

        private void require(int length) {
            if (length > remaining()) {
                throw invalid("Truncated ELF .eh_frame data");
            }
        }

        private void skip(int length) {
            require(length);
            position += length;
        }
    }

    private static final class Match {
        private Symbol defined;
        private boolean invalid;

        private void add(Symbol symbol) {
            if (symbol.type == STT_GNU_IFUNC || symbol.section == 0 || symbol.type != STT_FUNC
                    || symbol.value <= 0) {
                invalid = true;
                return;
            }
            if (defined == null) {
                defined = symbol;
            } else if (defined.value != symbol.value || defined.size != symbol.size
                    || defined.section != symbol.section || defined.type != symbol.type) {
                throw invalid("Conflicting definitions of an ELF symbol");
            }
        }

        private Symbol resolved(String name) {
            if (defined == null) {
                if (invalid) {
                    throw invalid("Symbol is not a defined function: " + name);
                }
                return null;
            }
            if (invalid) {
                throw invalid("Symbol has conflicting or non-function definitions: " + name);
            }
            return defined;
        }
    }
}
