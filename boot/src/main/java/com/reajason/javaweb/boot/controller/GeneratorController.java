package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.dto.GenerateRequest;
import com.reajason.javaweb.boot.dto.GenerateResponse;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.packer.AggregatePacker;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.jar.JarPacker;
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
    public GenerateResponse generate(@RequestBody GenerateRequest request) {
        ShellConfig shellConfig = request.getShellConfig();
        ShellToolConfig shellToolConfig = request.parseShellToolConfig();
        InjectorConfig injectorConfig = request.getInjectorConfig();
        GenerateResult generateResult = MemShellGenerator.generate(shellConfig, injectorConfig, shellToolConfig);
        Packer packer = request.getPacker().getInstance();
        if (packer instanceof JarPacker) {
            return new GenerateResponse(generateResult, Base64.getEncoder().encodeToString(((JarPacker) packer).packBytes(generateResult.toJarPackerConfig())));
        } else if (packer instanceof AggregatePacker) {
            return new GenerateResponse(generateResult, ((AggregatePacker) packer).packAll(generateResult.toClassPackerConfig()));
        } else {
            return new GenerateResponse(generateResult, packer.pack(generateResult.toClassPackerConfig()));
        }
    }
}