package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.dto.MemShellGenerateRequest;
import com.reajason.javaweb.boot.dto.MemShellGenerateResponse;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.JarPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

/**
 * @author ReaJason
 * @since 2024/12/18
 */
@RestController
@RequestMapping("/api/memshell/generate")
@CrossOrigin("*")
public class MemShellGeneratorController {

    @PostMapping
    public MemShellGenerateResponse generate(@RequestBody MemShellGenerateRequest request) {
        ShellConfig shellConfig = request.getShellConfig();
        ShellToolConfig shellToolConfig = request.parseShellToolConfig();
        InjectorConfig injectorConfig = request.getInjectorConfig();
        MemShellResult generateResult = MemShellGenerator.generate(shellConfig, injectorConfig, shellToolConfig);
        if (request.getPackerSpec() == null) {
            throw new IllegalArgumentException("packerSpec is required");
        }
        Packers packers = Packers.fromName(request.getPackerSpec().getName());
        Packer<?> packer = packers.getInstance();
        if (packer instanceof JarPacker) {
            JarPackerConfig<?> jarPackerConfig = generateResult.toJarPackerConfig();
            return new MemShellGenerateResponse(generateResult, Base64.getEncoder().encodeToString(((JarPacker) packer).packBytes(jarPackerConfig)));
        }
        ClassPackerConfig classPackerConfig = generateResult.toClassPackerConfig();
        classPackerConfig.setCustomConfig(packer.resolveCustomConfig(request.getPackerSpec().getConfig()));
        return new MemShellGenerateResponse(generateResult, packer.pack(classPackerConfig));
    }
}
