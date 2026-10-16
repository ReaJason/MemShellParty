package com.reajason.javaweb.packer.deserialize;

import lombok.SneakyThrows;
import com.reajason.javaweb.utils.Base64Utils;

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
        return Base64Utils.encodeBase64String(bos.toByteArray());
    }
}
