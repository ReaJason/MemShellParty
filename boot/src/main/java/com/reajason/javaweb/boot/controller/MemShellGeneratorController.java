package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.dto.MemShellGenerateRequest;
import com.reajason.javaweb.boot.dto.MemShellGenerateResponse;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
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
@RequestMapping("/memshell/generate")
@CrossOrigin("*")
public class MemShellGeneratorController {
    @PostMapping
    public MemShellGenerateResponse generate(@RequestBody MemShellGenerateRequest request) {
        ShellConfig shellConfig = request.getShellConfig();
        ShellToolConfig shellToolConfig = request.parseShellToolConfig();
        InjectorConfig injectorConfig = request.getInjectorConfig();
        MemShellResult generateResult = MemShellGenerator.generate(shellConfig, injectorConfig, shellToolConfig);
        Packer packer = request.getPacker().getInstance();
        if (packer instanceof JarPacker) {
            return new MemShellGenerateResponse(generateResult, Base64.getEncoder().encodeToString(((JarPacker) packer).packBytes(generateResult.toJarPackerConfig())));
        } else if (packer instanceof AggregatePacker) {
            return new MemShellGenerateResponse(generateResult, ((AggregatePacker) packer).packAll(generateResult.toClassPackerConfig()));
        } else {
            return new MemShellGenerateResponse(generateResult, packer.pack(generateResult.toClassPackerConfig()));
        }
    }
}