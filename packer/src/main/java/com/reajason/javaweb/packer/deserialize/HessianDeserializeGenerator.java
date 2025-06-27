package com.reajason.javaweb.packer.deserialize;

import com.caucho.hessian.io.Hessian2Output;
import com.caucho.hessian.io.HessianOutput;
import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayOutputStream;

/**
 * @author ReaJason
 * @since 2025/2/19
 */
public class HessianDeserializeGenerator {
    @SneakyThrows
    public static String generate(Object obj) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        HessianOutput hessianOutput = new HessianOutput(bos);
        hessianOutput.getSerializerFactory().setAllowNonSerializable(true);
        hessianOutput.writeObject(obj);
        hessianOutput.close();
        return Base64.encodeBase64String(bos.toByteArray());
    }

    @SneakyThrows
    public static String generate2(Object obj) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Hessian2Output hessian2Output = new Hessian2Output(bos);
        hessian2Output.getSerializerFactory().setAllowNonSerializable(true);
        hessian2Output.writeObject(obj);
        hessian2Output.close();
        return Base64.encodeBase64String(bos.toByteArray());
    }
}
