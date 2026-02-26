package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.dto.ProbeShellGenerateRequest;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateResponse;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import org.springframework.web.bind.annotation.*;

/**
 * @author ReaJason
 * @since 2025/8/10
 */
@RestController
@RequestMapping("/api/probe/generate")
@CrossOrigin("*")
public class ProbeShellGeneratorController {
    @PostMapping
    public ProbeShellGenerateResponse generate(@RequestBody ProbeShellGenerateRequest request) {
        ProbeConfig probeConfig = request.getProbeConfig();
        ProbeContentConfig probeContentConfig = request.parseProbeContentConfig();
        ProbeShellResult generateResult = ProbeShellGenerator.generate(probeConfig, probeContentConfig);
        if (request.getPackerSpec() == null) {
            throw new IllegalArgumentException("packerSpec is required");
        }
        Packers packers = Packers.fromName(request.getPackerSpec().getName());
        Packer packer = packers.getInstance();
        ClassPackerConfig classPackerConfig = generateResult.toClassPackerConfig();
        classPackerConfig.setCustomConfig(packer.resolveCustomConfig(request.getPackerSpec().getConfig()));
        return new ProbeShellGenerateResponse(generateResult, packer.pack(classPackerConfig));
    }
}
