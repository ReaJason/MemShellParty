package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.dto.ProbeShellGenerateRequest;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateResponse;
import com.reajason.javaweb.boot.service.GenerationService;
import org.springframework.web.bind.annotation.*;

/**
 * @author ReaJason
 * @since 2025/8/10
 */
@RestController
@RequestMapping("/api/probe/generate")
@CrossOrigin("*")
public class ProbeShellGeneratorController {

    private final GenerationService generationService;

    public ProbeShellGeneratorController(GenerationService generationService) {
        this.generationService = generationService;
    }

    @PostMapping
    public ProbeShellGenerateResponse generate(@RequestBody ProbeShellGenerateRequest request) {
        return generationService.generateProbeShell(request);
    }
}
