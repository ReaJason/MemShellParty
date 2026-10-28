package com.reajason.javaweb.vul.springboot1.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
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
    public String base64ClassLoader(@RequestParam(value = "data", required = false) String data,
                                    @RequestBody(required = false) String body) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(data == null ? body : data);
        Object o = defineClass(null, bytes, 0, bytes.length).newInstance();
        return o.toString();
    }
}
