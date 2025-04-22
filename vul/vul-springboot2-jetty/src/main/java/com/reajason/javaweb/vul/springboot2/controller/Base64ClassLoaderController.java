package com.reajason.javaweb.vul.springboot2.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@RestController
@RequestMapping("/b64")
public class Base64ClassLoaderController extends ClassLoader {
    @PostMapping
    public String base64ClassLoader(String data) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(data);
        Object o = defineClass(null, bytes, 0, bytes.length).newInstance();
        return o.toString();
    }
}
