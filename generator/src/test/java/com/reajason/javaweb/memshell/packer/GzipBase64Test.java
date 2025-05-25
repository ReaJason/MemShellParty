package com.reajason.javaweb.memshell.packer;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.base64.GzipBase64Packer;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;



/**
 * @author ReaJason
 * @since 2025/1/22
 */
class GzipBase64Test {

    @Test
    @SneakyThrows
    void compress() {
        GenerateResult generateResult = new GenerateResult();
        generateResult.setInjectorBytes("hello world".getBytes());
        String pack = new GzipBase64Packer().pack(generateResult);
        assertEquals("hello world", new String(CommonUtil.gzipDecompress(Base64.getDecoder().decode(pack))));
    }
}