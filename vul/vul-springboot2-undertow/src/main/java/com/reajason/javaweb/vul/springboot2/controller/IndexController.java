package com.reajason.javaweb.vul.springboot2.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@RestController
public class IndexController {

    @RequestMapping("/test")
    public String test() {
        return "";
    }

    @GetMapping("/")
    public String index() {
        return "hello";
    }
}
