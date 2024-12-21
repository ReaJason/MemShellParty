package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.GeneratorMain;
import com.reajason.javaweb.boot.dto.GenerateRequest;
import com.reajason.javaweb.boot.dto.GenerateResponse;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * @author ReaJason
 * @since 2024/12/18
 */
@RestController
@RequestMapping("/generate")
@CrossOrigin("*")
public class GeneratorController {
    @PostMapping
    public ResponseEntity<?> generate(@RequestBody GenerateRequest request) {
        ShellConfig shellConfig = request.getShellConfig();
        ShellToolConfig shellToolConfig = request.parseShellToolConfig();
        InjectorConfig injectorConfig = request.getInjectorConfig();
        GenerateResult generateResult = GeneratorMain.generate(shellConfig, injectorConfig, shellToolConfig);
        String packResult = request.getPacker().getPacker().pack(generateResult);
        return ResponseEntity.ok(new GenerateResponse(generateResult, packResult));
    }
}
