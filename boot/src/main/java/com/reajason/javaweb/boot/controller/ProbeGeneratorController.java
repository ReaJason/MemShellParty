package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.dto.ProbeGenerateRequest;
import com.reajason.javaweb.boot.dto.ProbeGenerateResponse;
import com.reajason.javaweb.packer.AggregatePacker;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.probe.ProbeGenerator;
import com.reajason.javaweb.probe.ProbeResult;
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
public class ProbeGeneratorController {
    @PostMapping
    public ProbeGenerateResponse generate(@RequestBody ProbeGenerateRequest request) {
        ProbeConfig probeConfig = request.getProbeConfig();
        ProbeContentConfig probeContentConfig = request.parseProbeContentConfig();
        ProbeResult generateResult = ProbeGenerator.generate(probeConfig, probeContentConfig);
        Packer packer = request.getPacker().getInstance();
        if (packer instanceof AggregatePacker) {
            return new ProbeGenerateResponse(generateResult, ((AggregatePacker) packer).packAll(generateResult.toClassPackerConfig()));
        } else {
            return new ProbeGenerateResponse(generateResult, packer.pack(generateResult.toClassPackerConfig()));
        }
    }
}
