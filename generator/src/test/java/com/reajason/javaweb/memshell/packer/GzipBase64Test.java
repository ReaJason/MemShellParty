package com.reajason.javaweb.memshell.packer;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Test;

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
        String pack = new GzipBase64().pack(generateResult);
        assertEquals("hello world", new String(CommonUtil.gzipDecompress(Base64.decodeBase64(pack))));
    }
}