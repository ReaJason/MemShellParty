package com.reajason.javaweb.boot.mcp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 把生成的载荷写入输出目录，并回传路径与摘要。
 * <p>
 * 安全约束：调用方提供的名称一律当作「不可信输入」处理。落盘前先取 basename、
 * 剔除不安全字符，再断言最终路径仍位于输出目录内。文件名中的点号被替换掉，
 * 因此 {@code ..} 无法幸存为上级目录引用。
 *
 * @author ReaJason
 */
public class McpPayloadWriter {

    public static final int MAX_BASE_NAME_LENGTH = 100;

    private static final String DEFAULT_BASE_NAME = "payload";
    private static final Pattern UNSAFE_NAME_CHARS = Pattern.compile("[^A-Za-z0-9_-]");
    private static final Pattern UNSAFE_EXTENSION_CHARS = Pattern.compile("[^A-Za-z0-9]");

    private final Path outputDir;

    public McpPayloadWriter(Path outputDir) throws IOException {
        this.outputDir = outputDir.toAbsolutePath().normalize();
        Files.createDirectories(this.outputDir);
    }

    public Path outputDir() {
        return outputDir;
    }

    /**
     * 清洗为安全的文件名主干：取 basename、把不安全字符替换为下划线、限长。
     * <p>
     * 点号不在允许字符集内，故 {@code ..} 会被消解为 {@code __}。
     */
    public static String sanitizeBaseName(String raw) {
        if (raw == null) {
            return DEFAULT_BASE_NAME;
        }
        String baseName = raw;
        int separator = Math.max(baseName.lastIndexOf('/'), baseName.lastIndexOf('\\'));
        if (separator >= 0) {
            baseName = baseName.substring(separator + 1);
        }
        if (baseName.isBlank()) {
            return DEFAULT_BASE_NAME;
        }
        String cleaned = UNSAFE_NAME_CHARS.matcher(baseName).replaceAll("_");
        if (cleaned.length() > MAX_BASE_NAME_LENGTH) {
            cleaned = cleaned.substring(0, MAX_BASE_NAME_LENGTH);
        }
        return cleaned.isEmpty() ? DEFAULT_BASE_NAME : cleaned;
    }

    /**
     * 写入单个载荷文件。
     */
    public WrittenFile writeSingle(String baseName, String extension, String content) throws IOException {
        String fileName = sanitizeBaseName(baseName) + sanitizeExtension(extension);
        return writeResolved(resolveSafe(outputDir, fileName), content);
    }

    /**
     * 写入聚合打包器产出的多个载荷，置于以 {@code baseName} 命名的子目录中。
     */
    public List<WrittenFile> writeAggregate(String baseName, Map<String, String> payloads) throws IOException {
        Path directory = resolveSafe(outputDir, sanitizeBaseName(baseName));
        Files.createDirectories(directory);

        List<WrittenFile> written = new ArrayList<>(payloads.size());
        Set<Path> used = new LinkedHashSet<>(payloads.size());
        for (Map.Entry<String, String> entry : payloads.entrySet()) {
            String fileName = sanitizeBaseName(entry.getKey()) + ".txt";
            Path target = resolveSafe(directory, fileName);
            // 不同 key 清洗后可能重名，追加序号避免互相覆盖丢载荷
            int suffix = 2;
            while (!used.add(target)) {
                target = resolveSafe(directory, sanitizeBaseName(entry.getKey()) + "-" + suffix++ + ".txt");
            }
            written.add(writeResolved(target, entry.getValue()));
        }
        return written;
    }

    private static String sanitizeExtension(String extension) {
        if (extension == null || extension.isBlank()) {
            return "";
        }
        String cleaned = UNSAFE_EXTENSION_CHARS.matcher(extension).replaceAll("");
        return cleaned.isEmpty() ? "" : "." + cleaned;
    }

    /**
     * 归一化后断言仍在基准目录内——清洗之外的兜底防线。
     */
    private static Path resolveSafe(Path baseDir, String name) throws IOException {
        Path resolved = baseDir.resolve(name).normalize();
        if (!resolved.startsWith(baseDir)) {
            throw new IOException("resolved path escapes output directory: " + name);
        }
        return resolved;
    }

    private static WrittenFile writeResolved(Path target, String content) throws IOException {
        byte[] bytes = content == null ? new byte[0] : content.getBytes(StandardCharsets.UTF_8);
        Files.write(target, bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
        return new WrittenFile(target.toString(), sha256Hex(bytes), bytes.length);
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
