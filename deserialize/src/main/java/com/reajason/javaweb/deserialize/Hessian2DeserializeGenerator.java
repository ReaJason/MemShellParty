package com.reajason.javaweb.deserialize;

import com.caucho.hessian.io.Hessian2Output;
import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;

/**
 * @author ReaJason
 * @since 2025/2/19
 */
public class Hessian2DeserializeGenerator {
    @SneakyThrows
    public static byte[] generate(byte[] bytes, String className, DeserializeConfig config) {
        PayloadType payloadType = config.getPayloadType();
        Object obj = payloadType.getPayload().generate(bytes, className);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Hessian2Output hessian2Output = new Hessian2Output(bos);
        hessian2Output.getSerializerFactory().setAllowNonSerializable(true);
        hessian2Output.writeObject(obj);
        hessian2Output.close();
        return bos.toByteArray();
    }
}
