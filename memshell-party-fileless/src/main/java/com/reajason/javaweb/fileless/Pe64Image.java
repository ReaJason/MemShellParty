package com.reajason.javaweb.fileless;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Minimal PE32+ parser for a DLL that is already mapped in the current process. */
final class Pe64Image {
    private static final int IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    private static final int IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    private static final int MAX_IMAGE_SIZE = 256 * 1024 * 1024;
    private static final int MAX_FUNCTION_SIZE = 16 * 1024 * 1024;

    private final long base;
    private final byte[] image;
    private final Section[] sections;
    private final Function[] functions;
    private final int exportDirectory;
    private final int exportDirectorySize;

    private Pe64Image(long base, byte[] image) {
        if (base == 0 || image == null || image.length < 0x1000 || image.length > MAX_IMAGE_SIZE) {
            throw invalid("Invalid mapped PE image size");
        }
        this.base = base;
        this.image = image;
        if (u16(0) != 0x5a4d) {
            throw invalid("Mapped image has no DOS signature");
        }
        int pe = i32(0x3c);
        range(pe, 24);
        if (i32(pe) != 0x00004550 || u16(pe + 4) != IMAGE_FILE_MACHINE_AMD64) {
            throw invalid("Mapped DLL is not a PE32+ AMD64 image");
        }
        int sectionCount = u16(pe + 6);
        int optionalSize = u16(pe + 20);
        int optional = pe + 24;
        if (sectionCount <= 0 || sectionCount > 96 || optionalSize < 112
                || optional + optionalSize > image.length || u16(optional) != 0x20b) {
            throw invalid("Invalid PE32+ headers");
        }
        int directoryCount = i32(optional + 108);
        if (directoryCount < 4 || optionalSize < 112 + 4 * 8) {
            throw invalid("PE image has no export/exception directories");
        }
        int directories = optional + 112;
        exportDirectory = i32(directories);
        exportDirectorySize = i32(directories + 4);
        int exceptionDirectory = i32(directories + 3 * 8);
        int exceptionSize = i32(directories + 3 * 8 + 4);
        if (exportDirectory == 0 || exportDirectorySize < 40
                || exceptionDirectory == 0 || exceptionSize <= 0 || exceptionSize % 12 != 0
                || exceptionSize / 12 > 1000000) {
            throw invalid("Invalid PE export or runtime-function directory");
        }
        range(exportDirectory, exportDirectorySize);
        range(exceptionDirectory, exceptionSize);

        int sectionOffset = optional + optionalSize;
        range(sectionOffset, sectionCount * 40);
        sections = new Section[sectionCount];
        for (int i = 0; i < sectionCount; i++) {
            int offset = sectionOffset + i * 40;
            int virtualSize = i32(offset + 8);
            int virtualAddress = i32(offset + 12);
            int characteristics = i32(offset + 36);
            if (virtualAddress < 0 || virtualSize < 0
                    || virtualAddress + virtualSize < virtualAddress) {
                throw invalid("Invalid PE section range");
            }
            sections[i] = new Section(virtualAddress, virtualSize, characteristics);
        }
        int count = exceptionSize / 12;
        functions = new Function[count];
        int previousEnd = 0;
        for (int i = 0; i < count; i++) {
            int begin = i32(exceptionDirectory + i * 12);
            int end = i32(exceptionDirectory + i * 12 + 4);
            if (begin < 0 || end <= begin || end - begin > MAX_FUNCTION_SIZE
                    || begin < previousEnd || executableSection(begin, end - begin) == null) {
                throw invalid("Invalid or overlapping PE runtime function");
            }
            functions[i] = new Function(begin, end);
            previousEnd = end;
        }
    }

    static Pe64Image parseMapped(byte[] image, long base) {
        return new Pe64Image(base, image);
    }

    static Pe64Image map(long base) {
        byte[] header = WindowsMemory.read(base, 4096);
        if (u16(header, 0) != 0x5a4d) {
            throw invalid("Resolved module has no DOS signature");
        }
        int pe = i32(header, 0x3c);
        if (pe < 0 || pe + 24 + 112 > header.length || i32(header, pe) != 0x00004550) {
            throw invalid("Resolved module has invalid PE headers");
        }
        int optional = pe + 24;
        int size = i32(header, optional + 56);
        if (size < 4096 || size > MAX_IMAGE_SIZE) {
            throw invalid("Resolved module exceeds the PE image limit");
        }
        return new Pe64Image(base, WindowsMemory.read(base, size));
    }

    Export export(String name) {
        int directory = exportDirectory;
        int functionCount = i32(directory + 20);
        int nameCount = i32(directory + 24);
        int functionsAddress = i32(directory + 28);
        int namesAddress = i32(directory + 32);
        int ordinalsAddress = i32(directory + 36);
        if (functionCount <= 0 || functionCount > 1000000 || nameCount < 0 || nameCount > functionCount) {
            throw invalid("Invalid PE export counts");
        }
        range(functionsAddress, functionCount * 4);
        range(namesAddress, nameCount * 4);
        range(ordinalsAddress, nameCount * 2);
        Export result = null;
        for (int i = 0; i < nameCount; i++) {
            String candidate = cString(i32(namesAddress + i * 4));
            if (!name.equals(candidate)) {
                continue;
            }
            int ordinal = u16(ordinalsAddress + i * 2);
            if (ordinal >= functionCount) {
                throw invalid("Invalid PE export ordinal");
            }
            int rva = i32(functionsAddress + ordinal * 4);
            if (rva >= exportDirectory && rva < exportDirectory + exportDirectorySize) {
                throw invalid("Forwarded PE export is not executable: " + name);
            }
            if (result != null) {
                throw invalid("Duplicate PE export: " + name);
            }
            result = new Export(name, rva);
        }
        if (result == null) {
            throw invalid("Required PE export is missing: " + name);
        }
        return result;
    }

    Function exportFunction(String name) {
        return functionAt(export(name).rva);
    }

    Function functionAt(int rva) {
        Function result = findFunctionAt(rva);
        if (result == null) {
            throw invalid("PE runtime function starts at an unknown RVA: 0x" + Integer.toHexString(rva));
        }
        return result;
    }

    private Function findFunctionAt(int rva) {
        int low = 0;
        int high = functions.length - 1;
        while (low <= high) {
            int middle = (low + high) >>> 1;
            Function function = functions[middle];
            if (rva < function.begin) {
                high = middle - 1;
            } else if (rva >= function.begin) {
                if (rva == function.begin) {
                    return function;
                }
                low = middle + 1;
            }
        }
        return null;
    }

    Function[] directCallees(Function caller) {
        X86_64JPLISLayout.Call[] calls = X86_64JPLISLayout.directCalls(read(caller), caller.begin);
        List<Function> result = new ArrayList<Function>();
        for (int i = 0; i < calls.length; i++) {
            long target = calls[i].target;
            if (target != (int) target) {
                continue;
            }
            Function callee = findFunctionAt((int) target);
            if (callee != null) {
                result.add(callee);
            }
        }
        return result.toArray(new Function[result.size()]);
    }

    Function directTailTarget(Export wrapper) {
        Section section = executableSection(wrapper.rva, 1);
        if (section == null) {
            throw invalid("JNI export is not in an executable PE section");
        }
        int length = Math.min(64, section.virtualAddress + section.virtualSize - wrapper.rva);
        byte[] code = Arrays.copyOfRange(image, wrapper.rva, wrapper.rva + length);
        long target = X86_64JPLISLayout.directTailJumpPrefix(code, wrapper.rva);
        if (target != (int) target) {
            throw invalid("PE tail jump leaves the mapped image");
        }
        return functionAt((int) target);
    }

    Function directTailTarget(Function wrapper) {
        long target = X86_64JPLISLayout.directTailJump(read(wrapper), wrapper.begin);
        if (target != (int) target) {
            throw invalid("PE tail jump leaves the mapped image");
        }
        return functionAt((int) target);
    }

    Function uniqueCalleeWithReference(Function caller, String ascii) {
        Function[] callees = directCallees(caller);
        Function result = null;
        for (int i = 0; i < callees.length; i++) {
            if (!referencesAscii(callees[i], ascii)) {
                continue;
            }
            if (result != null && result.begin != callees[i].begin) {
                throw invalid("Ambiguous PE callee reference: " + ascii);
            }
            result = callees[i];
        }
        if (result == null) {
            throw invalid("No PE callee references " + ascii);
        }
        return result;
    }

    boolean referencesAscii(Function function, String ascii) {
        byte[] needle = asciiBytes(ascii);
        byte[] code = read(function);
        for (int offset = 0; offset + needle.length <= image.length; offset++) {
            boolean match = true;
            for (int i = 0; i < needle.length; i++) {
                if (image[offset + i] != needle[i]) {
                    match = false;
                    break;
                }
            }
            if (match && X86_64JPLISLayout.hasRipReference(code, function.begin, offset)) {
                return true;
            }
        }
        return false;
    }

    byte[] read(Function function) {
        return read(function.begin, function.end - function.begin);
    }

    byte[] read(Export export, int length) {
        return read(export.rva, length);
    }

    byte[] read(int rva, int length) {
        range(rva, length);
        return Arrays.copyOfRange(image, rva, rva + length);
    }

    long address(Function function) {
        return address(function.begin, function.end - function.begin);
    }

    long address(Export export, int length) {
        return address(export.rva, length);
    }

    long address(int rva, int length) {
        if (rva < 0 || length < 0 || rva + length < rva) {
            throw invalid("Invalid PE address range");
        }
        range(rva, length);
        if (base + rva < base) {
            throw invalid("PE native address overflow");
        }
        return base + rva;
    }

    private Section executableSection(int rva, int length) {
        for (int i = 0; i < sections.length; i++) {
            Section section = sections[i];
            if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
                    && rva >= section.virtualAddress
                    && rva + length <= section.virtualAddress + section.virtualSize) {
                return section;
            }
        }
        return null;
    }

    private String cString(int rva) {
        range(rva, 1);
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < 4096; i++) {
            int value = u8(rva + i);
            if (value == 0) {
                return result.toString();
            }
            if (value < 0x20 || value > 0x7e) {
                throw invalid("Non-ASCII PE export name");
            }
            result.append((char) value);
        }
        throw invalid("Unterminated PE export name");
    }

    private void range(int rva, int length) {
        if (rva < 0 || length < 0 || rva + length < rva || rva + length > image.length) {
            throw invalid("PE directory exceeds the mapped image");
        }
    }

    private int u8(int offset) {
        range(offset, 1);
        return image[offset] & 0xff;
    }

    private int u16(int offset) {
        range(offset, 2);
        return u8(offset) | u8(offset + 1) << 8;
    }

    private int i32(int offset) {
        range(offset, 4);
        return u8(offset) | u8(offset + 1) << 8 | u8(offset + 2) << 16 | u8(offset + 3) << 24;
    }

    private static int u16(byte[] bytes, int offset) {
        return bytes[offset] & 0xff | (bytes[offset + 1] & 0xff) << 8;
    }

    private static int i32(byte[] bytes, int offset) {
        return bytes[offset] & 0xff | (bytes[offset + 1] & 0xff) << 8
                | (bytes[offset + 2] & 0xff) << 16 | (bytes[offset + 3] & 0xff) << 24;
    }

    private static byte[] asciiBytes(String value) {
        byte[] result = new byte[value.length()];
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c > 0x7f) {
                throw new IllegalArgumentException("PE reference must be ASCII");
            }
            result[i] = (byte) c;
        }
        return result;
    }

    private static UnsupportedOperationException invalid(String message) {
        return new UnsupportedOperationException(message + "; native state was not changed");
    }

    static final class Export {
        final int rva;

        Export(String name, int rva) {
            this.rva = rva;
        }
    }

    static final class Function {
        final int begin;
        final int end;

        Function(int begin, int end) {
            this.begin = begin;
            this.end = end;
        }
    }

    private static final class Section {
        private final int virtualAddress;
        private final int virtualSize;
        private final int characteristics;

        private Section(int virtualAddress, int virtualSize, int characteristics) {
            this.virtualAddress = virtualAddress;
            this.virtualSize = virtualSize;
            this.characteristics = characteristics;
        }
    }
}
