package com.reajason.javaweb.boot.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @author ReaJason
 * @since 2024/12/19
 */
@Controller
public class ViewController {
    @GetMapping("/")
    public String index() {
        return "index";
    }
}
