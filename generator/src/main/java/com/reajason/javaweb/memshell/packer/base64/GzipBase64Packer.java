package com.reajason.javaweb.memshell.packer.base64;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Base64;

/**
 * @author ReaJason
 * @since 2025/1/22
 */
public class GzipBase64Packer implements Packer {
    @Override
    @SneakyThrows
    public String pack(GenerateResult generateResult) {
        return Base64.encodeBase64String(CommonUtil.gzipCompress(generateResult.getInjectorBytes()));
    }
}
