package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.boot.dto.GenerateRequest;
import com.reajason.javaweb.boot.dto.GenerateResponse;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.packer.AggregatePacker;
import com.reajason.javaweb.memshell.packer.Packer;
import com.reajason.javaweb.memshell.packer.jar.JarPacker;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

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
        GenerateResult generateResult = MemShellGenerator.generate(shellConfig, injectorConfig, shellToolConfig);
        Packer packer = request.getPacker().getInstance();
        if (packer instanceof JarPacker) {
            return ResponseEntity.ok(new GenerateResponse(generateResult, Base64.getEncoder().encodeToString(((JarPacker) packer).packBytes(generateResult))));
        } else if (packer instanceof AggregatePacker) {
            return ResponseEntity.ok(new GenerateResponse(generateResult, ((AggregatePacker) packer).packAll(generateResult)));
        } else {
            return ResponseEntity.ok(new GenerateResponse(generateResult, packer.pack(generateResult)));
        }
    }
}