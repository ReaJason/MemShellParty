package com.reajason.javaweb.vul.springboot2.controller;

import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@RestController
@RequestMapping("/spel")
public class SpELController {

    @PostMapping
    public ResponseEntity<?> spel(String data) {
        return ResponseEntity.ok().body(String.valueOf(new SpelExpressionParser().parseExpression(data).getValue(new StandardEvaluationContext())));
    }
}
