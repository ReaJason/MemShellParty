package com.reajason.javaweb.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.charset.Charset;

/**
 * 流读写工具，语义与 {@code org.apache.commons.io.IOUtils} 对齐。
 * <p>
 * 项目原先通过 {@code commons-io} 传递依赖使用这些方法，为去掉该依赖，这里基于 JDK 重新实现。
 * 与 commons-io 一致：本类不关闭任何传入的流，由调用方负责；读取类方法在流为 {@code null} 时返回 {@code null}。
 *
 * @author ReaJason
 */
public class IOUtils {

    private static final int BUFFER_SIZE = 8192;

    private IOUtils() {
    }

    /**
     * 读取全部字节，流为 {@code null} 时返回 {@code null}
     */
    public static byte[] toByteArray(InputStream input) throws IOException {
        if (input == null) {
            return null;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        copy(input, out);
        return out.toByteArray();
    }

    /**
     * 按指定字符集读取全部文本，流为 {@code null} 时返回 {@code null}
     */
    public static String toString(InputStream input, Charset charset) throws IOException {
        if (input == null) {
            return null;
        }
        Reader reader = new InputStreamReader(input, charset);
        StringBuilder sb = new StringBuilder();
        char[] buffer = new char[BUFFER_SIZE];
        int length;
        while ((length = reader.read(buffer)) != -1) {
            sb.append(buffer, 0, length);
        }
        return sb.toString();
    }

    /**
     * 拷贝剩余字节，返回拷贝长度；任一入参为 {@code null} 时返回 {@code -1}
     */
    public static int copy(InputStream input, OutputStream output) throws IOException {
        if (input == null || output == null) {
            return -1;
        }
        byte[] buffer = new byte[BUFFER_SIZE];
        long count = 0;
        int length;
        while ((length = input.read(buffer)) != -1) {
            output.write(buffer, 0, length);
            count += length;
        }
        return (int) count;
    }
}
