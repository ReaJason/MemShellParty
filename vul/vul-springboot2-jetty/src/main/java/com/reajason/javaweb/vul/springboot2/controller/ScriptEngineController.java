package com.reajason.javaweb.vul.springboot2.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@RestController
@RequestMapping("/js")
public class ScriptEngineController {

    @PostMapping
    public ResponseEntity<?> js(String data) throws ScriptException {
        return ResponseEntity.ok().body(String.valueOf(new ScriptEngineManager().getEngineByName("js").eval(data)));
    }
}
