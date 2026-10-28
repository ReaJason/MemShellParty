package com.reajason.javaweb.bytecode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

/**
 * 类字节的文本编码：普通 Base64 或 GzipBase64（gzip 后 Base64）。
 * 与 {@link ClassBytesDecoder} 互为逆操作，生成工具的输出格式与输入识别共用同一套约定。
 */
public final class ClassBytesEncoder {

    private ClassBytesEncoder() {
    }

    /**
     * @param gzipBase64 {@code true} = 先 gzip 再 Base64，{@code false} = 普通 Base64
     */
    public static String encode(byte[] classBytes, boolean gzipBase64) {
        if (classBytes == null) {
            throw new IllegalArgumentException("类字节为空");
        }
        return Base64.getEncoder().encodeToString(gzipBase64 ? gzip(classBytes) : classBytes);
    }

    public static byte[] gzip(byte[] bytes) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, bytes.length / 2));
        GZIPOutputStream gzip = null;
        try {
            gzip = new GZIPOutputStream(out);
            gzip.write(bytes);
            gzip.finish();
            return out.toByteArray();
        } catch (IOException ex) {
            throw new IllegalStateException("Gzip 压缩失败：" + ex.getMessage(), ex);
        } finally {
            if (gzip != null) {
                try {
                    gzip.close();
                } catch (IOException ignored) {
                    // 结果已经读到内存，关流失败不影响输出
                }
            }
        }
    }
}
