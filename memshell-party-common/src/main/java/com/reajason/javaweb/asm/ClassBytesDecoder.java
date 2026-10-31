package com.reajason.javaweb.asm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

/**
 * 反编译输入解码：把「Base64 / GzipBase64 文本」或「.class 文件字节」统一还原成
 * 类名 + 类字节（{@link DecodedClass}），交给反编译器或字节码工具。
 *
 * <p>输入形态自动识别，不用调用方先问用户「这是哪种」：gzip 魔数（1f 8b）→ 先解压，
 * class 魔数（cafebabe）→ 直接交给 ASM 读类名。只做解码与识别，不碰界面也不落文件；
 * 失败原因用中文 {@link IllegalArgumentException} 消息给出，界面直接展示。
 */
public class ClassBytesDecoder {

    /**
     * 类字节上限：与 Custom 面板的 .class 选择器同值 —— 内存马 class 远超此大小即可判定选错文件，
     * 同时挡住 gzip 解压炸弹（GzipBase64 的压缩比可以很大）。
     */
    public static final int MAX_CLASS_BYTES = 8 * 1024 * 1024;

    private static final int CLASS_MAGIC = 0xCAFEBABE;

    private final ClassNameParser classNameParser = new ClassNameParser();

    /**
     * Base64 / GzipBase64 文本 → 类信息。文本里的换行与空格（粘贴常见）先整体去掉。
     *
     * @throws IllegalArgumentException 输入为空、Base64 非法、解压失败或不是 class 字节
     */
    public DecodedClass decodeBase64(String base64Text) {
        if (base64Text == null || base64Text.trim().isEmpty()) {
            throw new IllegalArgumentException("输入为空：请粘贴 Base64 / GzipBase64 文本");
        }
        String compact = base64Text.replaceAll("\\s", "");
        if (compact.length() > MAX_CLASS_BYTES * 2) {
            throw new IllegalArgumentException("编码输入过大，解压后的类字节上限为 "
                    + MAX_CLASS_BYTES / 1024 / 1024 + " MB");
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(compact);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Base64 解码失败：请确认输入是合法的 Base64 / GzipBase64 文本");
        }
        return decodeClassBytes(raw);
    }

    /**
     * 原始字节（.class 文件内容 / Base64 解码结果）→ 类信息：gzip 则解压，再解析类名。
     *
     * @throws IllegalArgumentException 输入为空、解压失败、不是 class 字节、类过大或类名解析失败
     */
    public DecodedClass decodeClassBytes(byte[] raw) {
        if (raw == null || raw.length == 0) {
            throw new IllegalArgumentException("输入为空：没有可反编译的字节");
        }
        boolean gzipped = isGzip(raw);
        byte[] classBytes = gzipped ? gunzip(raw) : raw;
        if (classBytes.length > MAX_CLASS_BYTES) {
            throw new IllegalArgumentException("类字节过大：" + classBytes.length / 1024 / 1024
                    + " MB，上限 " + MAX_CLASS_BYTES / 1024 / 1024 + " MB");
        }
        if (!isClassFile(classBytes)) {
            throw new IllegalArgumentException(gzipped
                    ? "解压后的数据不是 class 字节：请确认输入是 GzipBase64 压缩的类字节"
                    : "不是 class 字节：请确认输入是 Base64 / GzipBase64 文本或 .class 文件");
        }
        String className;
        try {
            className = classNameParser.parseClassName(classBytes);
        } catch (Exception ex) {
            throw new IllegalArgumentException("无法解析类名：" + messageOf(ex));
        }
        return new DecodedClass(className, classBytes, gzipped, raw.length);
    }

    private static boolean isGzip(byte[] bytes) {
        return bytes.length > 1 && (bytes[0] & 0xFF) == 0x1F && (bytes[1] & 0xFF) == 0x8B;
    }

    private static boolean isClassFile(byte[] bytes) {
        return bytes.length > 4
                && (bytes[0] & 0xFF) == ((CLASS_MAGIC >>> 24) & 0xFF)
                && (bytes[1] & 0xFF) == ((CLASS_MAGIC >>> 16) & 0xFF)
                && (bytes[2] & 0xFF) == ((CLASS_MAGIC >>> 8) & 0xFF)
                && (bytes[3] & 0xFF) == (CLASS_MAGIC & 0xFF);
    }

    private static byte[] gunzip(byte[] gzipped) {
        GZIPInputStream in = null;
        try {
            in = new GZIPInputStream(new ByteArrayInputStream(gzipped));
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(gzipped.length * 2, MAX_CLASS_BYTES));
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                if (out.size() + read > MAX_CLASS_BYTES) {
                    throw new IllegalArgumentException("解压后的类字节超过 " + MAX_CLASS_BYTES / 1024 / 1024 + " MB 上限");
                }
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } catch (IOException ex) {
            throw new IllegalArgumentException("Gzip 解压失败：数据不是有效的 GzipBase64");
        } finally {
            closeQuietly(in);
        }
    }

    private static void closeQuietly(GZIPInputStream in) {
        if (in != null) {
            try {
                in.close();
            } catch (IOException ignored) {
                // 解压结果已经读到内存里，关流失败不影响结果
            }
        }
    }

    private static String messageOf(Exception ex) {
        return ex.getMessage() == null ? String.valueOf(ex) : ex.getMessage();
    }

    /**
     * 解码结果：类名 + 类字节 + 输入是否 Gzip 压缩（界面据此说明「压缩 N bytes / 类 M bytes」）。
     */
    public static final class DecodedClass {

        private final String className;
        private final byte[] classBytes;
        private final boolean gzipped;
        private final int encodedSize;

        private DecodedClass(String className, byte[] classBytes, boolean gzipped, int encodedSize) {
            this.className = className;
            this.classBytes = classBytes;
            this.gzipped = gzipped;
            this.encodedSize = encodedSize;
        }

        public String getClassName() {
            return className;
        }

        public byte[] getClassBytes() {
            return classBytes;
        }

        /**
         * 输入是否是 GzipBase64（先解压才拿到的类字节）。
         */
        public boolean isGzipped() {
            return gzipped;
        }

        /**
         * 解压前的输入字节数（未压缩时与 {@link #getClassBytes()} 等长）。
         */
        public int getEncodedSize() {
            return encodedSize;
        }
    }
}
