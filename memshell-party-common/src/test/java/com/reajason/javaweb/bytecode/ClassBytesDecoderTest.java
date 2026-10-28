package com.reajason.javaweb.bytecode;

import com.reajason.javaweb.bytecode.fixtures.TriggerTarget;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 输入解码：Base64 / GzipBase64 文本与 .class 文件字节都还原成类名 + 类字节；
 * 不合法的输入给出可展示的中文原因。
 */
class ClassBytesDecoderTest {

    private static final ClassBytesDecoder DECODER = new ClassBytesDecoder();

    private static byte[] classBytes;
    private static String className;

    @BeforeAll
    static void readFixture() throws Exception {
        className = TriggerTarget.class.getName();
        InputStream in = TriggerTarget.class.getResourceAsStream(TriggerTarget.class.getSimpleName() + ".class");
        assertNotNull(in);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            classBytes = out.toByteArray();
        } finally {
            in.close();
        }
    }

    @Test
    void decodesPlainBase64() {
        ClassBytesDecoder.DecodedClass decoded = DECODER.decodeBase64(Base64.getEncoder().encodeToString(classBytes));

        assertEquals(className, decoded.getClassName());
        assertArrayEquals(classBytes, decoded.getClassBytes());
        assertFalse(decoded.isGzipped());
        assertEquals(classBytes.length, decoded.getEncodedSize());
    }

    @Test
    void decodesGzipBase64() {
        byte[] gzipped = ClassBytesEncoder.gzip(classBytes);

        ClassBytesDecoder.DecodedClass decoded = DECODER.decodeBase64(Base64.getEncoder().encodeToString(gzipped));

        assertEquals(className, decoded.getClassName());
        assertArrayEquals(classBytes, decoded.getClassBytes());
        assertTrue(decoded.isGzipped());
        assertEquals(gzipped.length, decoded.getEncodedSize());
    }

    @Test
    void ignoresWhitespaceInBase64Text() {
        String wrapped = wrap(Base64.getEncoder().encodeToString(classBytes), 64);

        ClassBytesDecoder.DecodedClass decoded = DECODER.decodeBase64(wrapped);

        assertEquals(className, decoded.getClassName());
        assertArrayEquals(classBytes, decoded.getClassBytes());
    }

    @Test
    void decodesRawClassFileBytes() {
        ClassBytesDecoder.DecodedClass decoded = DECODER.decodeClassBytes(classBytes);

        assertEquals(className, decoded.getClassName());
        assertArrayEquals(classBytes, decoded.getClassBytes());
        assertFalse(decoded.isGzipped());
    }

    @Test
    void decodesGzippedClassFileBytes() {
        ClassBytesDecoder.DecodedClass decoded = DECODER.decodeClassBytes(ClassBytesEncoder.gzip(classBytes));

        assertEquals(className, decoded.getClassName());
        assertArrayEquals(classBytes, decoded.getClassBytes());
        assertTrue(decoded.isGzipped());
    }

    @Test
    void rejectsEmptyInput() {
        assertTrue(messageOf(() -> DECODER.decodeBase64(null)).contains("输入为空"));
        assertTrue(messageOf(() -> DECODER.decodeBase64("   \n ")).contains("输入为空"));
        assertTrue(messageOf(() -> DECODER.decodeClassBytes(new byte[0])).contains("输入为空"));
    }

    @Test
    void rejectsInvalidBase64() {
        assertTrue(messageOf(() -> DECODER.decodeBase64("这不是 Base64 文本")).contains("Base64 解码失败"));
    }

    @Test
    void rejectsNonClassBytes() {
        assertTrue(messageOf(() -> DECODER.decodeClassBytes("hello world".getBytes())).contains("不是 class 字节"));
    }

    @Test
    void rejectsGzipOfNonClassData() throws Exception {
        byte[] gzipped = gzip("hello world".getBytes());

        assertTrue(messageOf(() -> DECODER.decodeClassBytes(gzipped)).contains("解压后的数据不是 class 字节"));
    }

    @Test
    void rejectsTruncatedClassBytes() {
        byte[] truncated = Arrays.copyOf(classBytes, 64);

        assertTrue(messageOf(() -> DECODER.decodeClassBytes(truncated)).contains("无法解析类名"));
    }

    @Test
    void rejectsOversizeClassBytes() {
        byte[] huge = new byte[ClassBytesDecoder.MAX_CLASS_BYTES + 1];
        huge[0] = (byte) 0xCA;
        huge[1] = (byte) 0xFE;
        huge[2] = (byte) 0xBA;
        huge[3] = (byte) 0xBE;

        assertTrue(messageOf(() -> DECODER.decodeClassBytes(huge)).contains("类字节过大"));
    }

    @Test
    void rejectsGzipBombDuringDecompression() throws Exception {
        byte[] bomb = gzip(new byte[ClassBytesDecoder.MAX_CLASS_BYTES + 1024]);

        assertTrue(messageOf(() -> DECODER.decodeClassBytes(bomb)).contains("超过"));
    }

    private static String messageOf(Runnable failing) {
        try {
            failing.run();
        } catch (IllegalArgumentException ex) {
            return ex.getMessage() == null ? "" : ex.getMessage();
        }
        throw new AssertionError("应当抛出 IllegalArgumentException");
    }

    private static String wrap(String text, int lineLength) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i += lineLength) {
            sb.append(text, i, Math.min(i + lineLength, text.length())).append('\n');
        }
        return sb.toString();
    }

    private static byte[] gzip(byte[] data) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPOutputStream gzip = new GZIPOutputStream(out);
        gzip.write(data);
        gzip.close();
        return out.toByteArray();
    }
}
