package com.reajason.javaweb.deserialize;

import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class DeserializeGenerator {

    @SneakyThrows
    public static byte[] generate(byte[] bytes, DeserializeConfig config) {
        PayloadType payloadType = config.getPayloadType();
        Object obj = payloadType.getPayload().generate(bytes);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        oos.flush();
        oos.close();
        return baos.toByteArray();
    }
}
