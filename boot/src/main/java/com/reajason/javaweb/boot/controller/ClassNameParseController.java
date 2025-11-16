package com.reajason.javaweb.boot.controller;

import org.springframework.asm.ClassReader;
import org.springframework.cglib.core.ClassNameReader;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;

/**
 * @author ReaJason
 * @since 2025/11/10
 */
@RestController
@CrossOrigin("*")
public class ClassNameParseController {

    @PostMapping("/className")
    public String className(@RequestBody String classBase64) {
        return ClassNameReader.getClassName(new ClassReader(Base64.getDecoder().decode(classBase64)));
    }
}
