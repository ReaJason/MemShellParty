package com.reajason.javaweb.memsell.packer;

import com.reajason.javaweb.config.GenerateResult;
import org.apache.commons.codec.binary.Base64;

/**
 * @author ReaJason
 * @since 2024/12/17
 */
public class Base64Packer implements Packer {
    @Override
    public String pack(GenerateResult generateResult) {
        return Base64.encodeBase64String(generateResult.getInjectorBytes());
    }
}
