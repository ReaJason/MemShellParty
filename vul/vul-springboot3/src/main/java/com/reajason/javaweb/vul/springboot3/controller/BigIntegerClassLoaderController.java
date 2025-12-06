package com.reajason.javaweb.vul.springboot3.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author ReaJason
 * @since 2025/12/6
 */
@RestController
@RequestMapping("/biginteger")
public class BigIntegerClassLoaderController extends ClassLoader {
    static byte[] decodeBigInteger(String bigIntegerStr) throws Exception {
        Class<?> decoderClass = Class.forName("java.math.BigInteger");
        return (byte[]) decoderClass.getMethod("toByteArray").invoke(decoderClass.getConstructor(String.class, int.class).newInstance(bigIntegerStr, Character.MAX_RADIX));
    }

    @PostMapping
    public void base64ClassLoader(String data) throws Exception {
        byte[] bytes = decodeBigInteger(data);
        defineClass(null, bytes, 0, bytes.length).newInstance();
    }
}
