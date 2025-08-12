package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.dto.ProbeShellGenerateRequest;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateResponse;
import com.reajason.javaweb.packer.AggregatePacker;
import com.reajason.javaweb.packer.Packer;
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
@RequestMapping("/probe/generate")
@CrossOrigin("*")
public class ProbeShellGeneratorController {
    @PostMapping
    public ProbeShellGenerateResponse generate(@RequestBody ProbeShellGenerateRequest request) {
        ProbeConfig probeConfig = request.getProbeConfig();
        ProbeContentConfig probeContentConfig = request.parseProbeContentConfig();
        ProbeShellResult generateResult = ProbeShellGenerator.generate(probeConfig, probeContentConfig);
        Packer packer = request.getPacker().getInstance();
        if (packer instanceof AggregatePacker) {
            return new ProbeShellGenerateResponse(generateResult, ((AggregatePacker) packer).packAll(generateResult.toClassPackerConfig()));
        } else {
            return new ProbeShellGenerateResponse(generateResult, packer.pack(generateResult.toClassPackerConfig()));
        }
    }
}
