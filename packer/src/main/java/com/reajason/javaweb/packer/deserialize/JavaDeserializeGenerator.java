package com.reajason.javaweb.packer.deserialize;

import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class JavaDeserializeGenerator {

    @SneakyThrows
    public static String generate(Object obj) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.flush();
        oos.close();
        return Base64.encodeBase64String(bos.toByteArray());
    }
}
