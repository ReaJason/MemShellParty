package com.reajason.javaweb.vul.springboot3.controller;

import ognl.Ognl;
import ognl.OgnlContext;
import ognl.OgnlException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
@RestController
@RequestMapping("/ognl")
public class OgnlController {
    @RequestMapping
    protected Object doPost(String data) {
        OgnlContext context = new OgnlContext();
        try {
            return Ognl.getValue(data, context, context.getRoot());
        } catch (OgnlException e) {
            throw new RuntimeException(e);
        }
    }
}
