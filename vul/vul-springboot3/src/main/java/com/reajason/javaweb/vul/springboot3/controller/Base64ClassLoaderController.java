package com.reajason.javaweb.vul.springboot3.controller;

import com.reajason.javaweb.vul.springboot3.ClassDefiner;
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
public class Base64ClassLoaderController {

    @PostMapping
    public String base64ClassLoader(String data) throws InstantiationException, IllegalAccessException {
        byte[] bytes = Base64.getDecoder().decode(data);
        Object o = ClassDefiner.defineClass(bytes).newInstance();
        return o.toString();
    }
}