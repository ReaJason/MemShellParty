package com.reajason.javaweb.boot.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author ReaJason
 * @since 2025/2/2
 */
@RestController
@CrossOrigin("*")
@RequestMapping("/version")
public class VersionController {

    @Value("${spring.application.version}")
    String version;

    @GetMapping
    public String version() {
        return version;
    }
}
