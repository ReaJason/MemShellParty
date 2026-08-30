package com.reajason.javaweb.vul.springboot3.controller;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2026/8/30
 */
@RestController
@RequestMapping("/freemarker")
public class FreemarkerController {
    @PostMapping
    public String freemarker(@RequestParam String data) throws IOException, TemplateException {
        Configuration configuration = new Configuration();
        configuration.setDefaultEncoding("UTF-8");
        Map<String, Object> input = new HashMap<>();
        input.put("object", new Object());
        Template template = new Template("templateName", new StringReader(data), configuration);
        StringWriter output = new StringWriter();
        template.process(input, output);
        return output.toString();
    }
}
