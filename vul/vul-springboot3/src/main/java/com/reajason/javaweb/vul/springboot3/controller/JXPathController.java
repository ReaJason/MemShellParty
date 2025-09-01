package com.reajason.javaweb.vul.springboot3.controller;

import org.apache.commons.jxpath.JXPathContext;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
@RestController
@RequestMapping("/jxpath")
public class JXPathController {
    @PostMapping
    protected Object doPost(String data) {
        JXPathContext context = JXPathContext.newContext(null);
        return context.getValue(data);
    }
}
