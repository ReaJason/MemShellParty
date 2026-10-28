package com.reajason.javaweb.fileless;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class NativeImage {
    private static final long PAGE_SIZE = 4096L;
    private final File file;
    private final Elf64File elf;
    private final long loadBias;
    private final Mapping[] mappings;

    private NativeImage(File file, List<Mapping> mappings) throws IOException {
        this.file = file;
        this.mappings = mappings.toArray(new Mapping[mappings.size()]);
        Elf64File parsed = null;
        boolean success = false;
        try {
            parsed = new Elf64File(file);
            loadBias = resolveLoadBias(parsed.getLoadSegments(), this.mappings);
            this.elf = parsed;
            success = true;
        } finally {
            if (!success && parsed != null) {
                parsed.close();
            }
        }
    }

    static NativeImage findLinux(String libraryName) throws IOException {
        List<NativeImage> images = findLinuxAll(libraryName);
        if (images.isEmpty()) {
            return null;
        }
        if (images.size() != 1) {
            closeAll(images);
            throw invalid("Multiple mapped images match " + libraryName);
        }
        return images.get(0);
    }

    static List<NativeImage> findLinuxAll(String libraryName) throws IOException {
        return findImages(libraryName, false);
    }

    static List<NativeImage> findLinuxFamily(String libraryPrefix) throws IOException {
        return findImages(libraryPrefix, true);
    }

    private static List<NativeImage> findImages(String name, boolean family) throws IOException {
        Map<String, List<Mapping>> byPath = readMappings(name, family);
        List<NativeImage> result = new ArrayList<NativeImage>();
        try {
            for (Map.Entry<String, List<Mapping>> entry : byPath.entrySet()) {
                result.add(new NativeImage(new File(entry.getKey()), entry.getValue()));
            }
            return result;
        } catch (IOException failure) {
            closeAll(result);
            throw failure;
        } catch (RuntimeException failure) {
            closeAll(result);
            throw failure;
        }
    }

    private static Map<String, List<Mapping>> readMappings(String name, boolean family) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"));
        try {
            Map<String, List<Mapping>> result = new LinkedHashMap<String, List<Mapping>>();
            String line;
            while ((line = reader.readLine()) != null) {
                Mapping mapping = Mapping.parse(line);
                if (mapping == null || !matches(mapping.path, name, family)) {
                    continue;
                }
                File file = new File(mapping.path);
                if (!file.isFile()) {
                    throw invalid("Mapped native image is inaccessible: " + mapping.path);
                }
                List<Mapping> mappings = result.get(mapping.path);
                if (mappings == null) {
                    mappings = new ArrayList<Mapping>();
                    result.put(mapping.path, mappings);
                }
                mappings.add(mapping);
            }
            return result;
        } finally {
            reader.close();
        }
    }

    private static boolean matches(String path, String name, boolean family) {
        if (path == null || !path.startsWith("/") || path.endsWith(" (deleted)")) {
            return false;
        }
        int separator = path.lastIndexOf('/');
        String base = separator >= 0 ? path.substring(separator + 1) : path;
        return family ? base.startsWith(name) && base.endsWith(".so") : base.equals(name);
    }

    static NativeImage fromMappings(File file, List<Mapping> mappings) throws IOException {
        if (mappings == null || mappings.isEmpty()) {
            throw new IllegalArgumentException("Native mappings are required");
        }
        return new NativeImage(file, mappings);
    }

    private static long resolveLoadBias(Elf64File.Segment[] segments, Mapping[] mappings) {
        List<Long> resolved = null;
        for (int i = 0; i < mappings.length; i++) {
            Mapping mapping = mappings[i];
            if (!mapping.readable) {
                continue;
            }
            List<Long> candidates = new ArrayList<Long>();
            for (int j = 0; j < segments.length; j++) {
                Elf64File.Segment segment = segments[j];
                long segmentOffset = alignDown(segment.fileOffset);
                long segmentAddress = alignDown(segment.virtualAddress);
                long fileEnd = alignUp(segment.fileOffset + segment.fileSize);
                if (mapping.executable != ((segment.flags & 1) != 0)
                        || mapping.offset < segmentOffset || mapping.offset >= fileEnd) {
                    continue;
                }
                long virtualAddress = segmentAddress + mapping.offset - segmentOffset;
                long bias = mapping.start - virtualAddress;
                if (bias < 0 || bias + virtualAddress != mapping.start) {
                    throw invalid("Invalid native load-bias calculation");
                }
                Long value = Long.valueOf(bias);
                if (!candidates.contains(value)) {
                    candidates.add(value);
                }
            }
            if (candidates.isEmpty()) {
                throw invalid("Native mapping does not match a file-backed PT_LOAD segment: "
                        + mapping.path + " offset=0x" + Long.toHexString(mapping.offset)
                        + " length=0x" + Long.toHexString(mapping.length()));
            }
            if (resolved == null) {
                resolved = candidates;
            } else {
                resolved.retainAll(candidates);
            }
            if (resolved.isEmpty()) {
                throw invalid("Inconsistent native load biases");
            }
        }
        if (resolved == null) {
            throw invalid("No usable native mappings");
        }
        if (resolved.size() != 1) {
            throw invalid("Ambiguous native PT_LOAD mapping");
        }
        return resolved.get(0).longValue();
    }

    boolean isAarch64() {
        return elf.isAarch64();
    }

    long address(Elf64File.Symbol symbol) {
        if (symbol == null) {
            throw new IllegalArgumentException("Native symbol is required");
        }
        elf.fileOffset(symbol.value, 1, true);
        return address(symbol.value, 1);
    }

    long address(long symbolValue) {
        elf.fileOffset(symbolValue, 1, true);
        return address(symbolValue, 1);
    }

    private long address(long virtualAddress, int length) {
        if (virtualAddress < 0 || virtualAddress + loadBias < virtualAddress) {
            throw invalid("Native address overflow");
        }
        long address = virtualAddress + loadBias;
        if (length < 0 || address + length < address) {
            throw invalid("Native address range overflow");
        }
        Mapping containing = null;
        for (int i = 0; i < mappings.length; i++) {
            Mapping mapping = mappings[i];
            if (mapping.executable && address >= mapping.start && address + length <= mapping.end) {
                if (containing != null) {
                    throw invalid("Ambiguous executable native mapping");
                }
                containing = mapping;
            }
        }
        if (containing == null) {
            throw invalid("Native range is not covered by one executable mapping");
        }
        return address;
    }

    byte[] readPatch(Elf64File.Symbol symbol, int length) throws IOException {
        address(symbol.value, length);
        return elf.read(symbol, 0L, length);
    }

    byte[] readFunction(Elf64File.Symbol symbol) throws IOException {
        address(symbol);
        return elf.readFunction(symbol);
    }

    Elf64File.Symbol functionAt(long virtualAddress) throws IOException {
        return elf.functionAt(virtualAddress);
    }

    Elf64File.Symbol findSymbol(String name) throws IOException {
        return elf.findSymbol(name);
    }

    Elf64File.Symbol[] findSymbols(String[] names) throws IOException {
        return elf.findSymbols(names);
    }

    File getFile() {
        return file;
    }

    void close() throws IOException {
        elf.close();
    }

    private static void closeAll(List<NativeImage> images) {
        for (int i = 0; i < images.size(); i++) {
            try {
                images.get(i).close();
            } catch (IOException ignored) {
            }
        }
    }

    private static long alignDown(long value) {
        return value & -PAGE_SIZE;
    }

    private static long alignUp(long value) {
        if (value < 0 || value + PAGE_SIZE - 1 < value) {
            throw invalid("Native segment range overflow");
        }
        return (value + PAGE_SIZE - 1) & -PAGE_SIZE;
    }

    private static UnsupportedOperationException invalid(String message) {
        return new UnsupportedOperationException(message + "; native state was not changed");
    }

    static final class Mapping {
        final long start;
        final long end;
        final long offset;
        final boolean readable;
        final boolean executable;
        final String path;

        Mapping(long start, long end, long offset, boolean readable, boolean executable, String path) {
            if (start < 0 || end <= start || offset < 0 || path == null) {
                throw new IllegalArgumentException("Invalid native mapping");
            }
            this.start = start;
            this.end = end;
            this.offset = offset;
            this.readable = readable;
            this.executable = executable;
            this.path = path;
        }

        long length() {
            return end - start;
        }

        private static Mapping parse(String line) {
            try {
                String[] fields = line.trim().split("\\s+", 6);
                if (fields.length != 6) {
                    return null;
                }
                String[] addresses = fields[0].split("-", 2);
                if (addresses.length != 2) {
                    return null;
                }
                long start = Long.parseLong(addresses[0], 16);
                long end = Long.parseLong(addresses[1], 16);
                long offset = Long.parseLong(fields[2], 16);
                String permissions = fields[1];
                return new Mapping(start, end, offset,
                        permissions.length() >= 1 && permissions.charAt(0) == 'r',
                        permissions.length() >= 3 && permissions.charAt(2) == 'x', fields[5]);
            } catch (RuntimeException ignored) {
                return null;
            }
        }
    }
}
