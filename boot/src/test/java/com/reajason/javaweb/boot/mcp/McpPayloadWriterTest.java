package com.reajason.javaweb.boot.mcp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author ReaJason
 */
class McpPayloadWriterTest {

    @TempDir
    Path tempDir;

    private McpPayloadWriter writer;

    @BeforeEach
    void setUp() throws IOException {
        writer = new McpPayloadWriter(tempDir);
    }

    @Test
    void writesSingleFileWithContentHashAndSize() throws IOException {
        WrittenFile file = writer.writeSingle("Tomcat-Godzilla-Filter", "b64", "payload-content");

        assertEquals("payload-content".getBytes(StandardCharsets.UTF_8).length, file.bytes());
        assertEquals(sha256Hex("payload-content"), file.sha256());
        assertEquals("payload-content", Files.readString(Path.of(file.path()), StandardCharsets.UTF_8));
        assertTrue(file.path().endsWith(".b64"), "expected .b64 suffix but was " + file.path());
    }

    @Test
    void writesAggregateFilesIntoItsOwnDirectory() throws IOException {
        Map<String, String> payloads = new LinkedHashMap<>();
        payloads.put("Base64", "aaa");
        payloads.put("ScriptEngine", "bbbb");

        List<WrittenFile> files = writer.writeAggregate("Tomcat-Godzilla-Filter", payloads);

        assertEquals(2, files.size());
        for (WrittenFile file : files) {
            assertTrue(Files.exists(Path.of(file.path())));
        }
        assertEquals("aaa", Files.readString(Path.of(files.get(0).path()), StandardCharsets.UTF_8));
        assertEquals("bbbb", Files.readString(Path.of(files.get(1).path()), StandardCharsets.UTF_8));
        assertEquals(3, files.get(0).bytes());
        assertEquals(4, files.get(1).bytes());
        assertNotEquals(files.get(0).path(), files.get(1).path());
    }

    @Test
    void sanitizeStripsPathTraversalToBaseName() {
        assertEquals("passwd", McpPayloadWriter.sanitizeBaseName("../../etc/passwd"));
        assertEquals("passwd", McpPayloadWriter.sanitizeBaseName("..\\..\\windows\\passwd"));
        assertEquals("passwd", McpPayloadWriter.sanitizeBaseName("/absolute/passwd"));
    }

    @Test
    void sanitizeReplacesUnsafeCharactersAndRejectsDotDot() {
        assertEquals("a_b", McpPayloadWriter.sanitizeBaseName("a b"));
        assertEquals("__", McpPayloadWriter.sanitizeBaseName(".."));
        assertEquals("_", McpPayloadWriter.sanitizeBaseName("."));
        assertEquals("___", McpPayloadWriter.sanitizeBaseName("..."));
        assertFalse(McpPayloadWriter.sanitizeBaseName("../../etc/passwd").contains(".."));
        // 结果只含文件名安全字符，且不含路径分隔符
        assertTrue(McpPayloadWriter.sanitizeBaseName("a/b/../../c").matches("[A-Za-z0-9_-]+"));
    }

    @Test
    void sanitizeFallsBackToDefaultWhenNothingUsable() {
        assertEquals("payload", McpPayloadWriter.sanitizeBaseName(null));
        assertEquals("payload", McpPayloadWriter.sanitizeBaseName(""));
        assertEquals("payload", McpPayloadWriter.sanitizeBaseName("   "));
    }

    @Test
    void sanitizeTruncatesOverlongNames() {
        String longName = "x".repeat(500);
        String sanitized = McpPayloadWriter.sanitizeBaseName(longName);
        assertTrue(sanitized.length() <= McpPayloadWriter.MAX_BASE_NAME_LENGTH, "was " + sanitized.length());
    }

    @Test
    void traversalAttemptCannotEscapeOutputDirectory() throws IOException {
        String evil = "../../../../../../tmp/memshell-escape-probe";

        WrittenFile file = writer.writeSingle(evil, "txt", "x");

        Path written = Path.of(file.path()).normalize();
        assertTrue(written.startsWith(tempDir.normalize()),
                "file escaped the output directory: " + written);
    }

    @Test
    void aggregateTraversalAttemptCannotEscapeOutputDirectory() throws IOException {
        Map<String, String> payloads = new LinkedHashMap<>();
        payloads.put("../../escape", "x");

        List<WrittenFile> files = writer.writeAggregate("../evil", payloads);

        for (WrittenFile file : files) {
            Path written = Path.of(file.path()).normalize();
            assertTrue(written.startsWith(tempDir.normalize()),
                    "file escaped the output directory: " + written);
        }
    }

    @Test
    void createsOutputDirectoryWhenMissing() throws IOException {
        Path nested = tempDir.resolve("a").resolve("b");
        assertFalse(Files.exists(nested));

        McpPayloadWriter nestedWriter = new McpPayloadWriter(nested);
        WrittenFile file = nestedWriter.writeSingle("x", "txt", "y");

        assertTrue(Files.exists(Path.of(file.path())));
    }

    @Test
    void overwritesExistingFileRatherThanAppending() throws IOException {
        WrittenFile first = writer.writeSingle("same", "txt", "first");
        writer.writeSingle("same", "txt", "second");

        assertEquals("second", Files.readString(Path.of(first.path()), StandardCharsets.UTF_8));
    }

    private static String sha256Hex(String content) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(content.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
