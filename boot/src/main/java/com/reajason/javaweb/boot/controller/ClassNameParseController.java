package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.service.ClassNameParseService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author ReaJason
 * @since 2025/11/10
 */
@RestController
@CrossOrigin("*")
public class ClassNameParseController {

    private final ClassNameParseService classNameParseService;

    public ClassNameParseController(ClassNameParseService classNameParseService) {
        this.classNameParseService = classNameParseService;
    }

    @PostMapping("/api/className")
    public String className(@RequestBody String classBase64) {
        return classNameParseService.parse(classBase64);
    }
}
