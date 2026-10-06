package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.dto.ProbeShellGenerateRequest;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateResponse;
import com.reajason.javaweb.boot.service.GenerationOutcome;
import com.reajason.javaweb.boot.service.ProbeGenerationService;
import com.reajason.javaweb.probe.ProbeShellResult;
import org.springframework.web.bind.annotation.*;

/**
 * @author ReaJason
 * @since 2025/8/10
 */
@RestController
@RequestMapping("/api/probe/generate")
@CrossOrigin("*")
public class ProbeShellGeneratorController {

    private final ProbeGenerationService generationService;

    public ProbeShellGeneratorController(ProbeGenerationService generationService) {
        this.generationService = generationService;
    }

    @PostMapping
    public ProbeShellGenerateResponse generate(@RequestBody ProbeShellGenerateRequest request) {
        GenerationOutcome<ProbeShellResult> outcome = generationService.generate(
                request.getProbeConfig(),
                request.parseProbeContentConfig(),
                request.getPacker());
        if (outcome.allPackResults() != null) {
            return new ProbeShellGenerateResponse(outcome.result(), outcome.allPackResults());
        }
        return new ProbeShellGenerateResponse(outcome.result(), outcome.packResult());
    }
}
