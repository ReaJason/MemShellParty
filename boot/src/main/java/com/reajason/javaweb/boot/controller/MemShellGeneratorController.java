package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.dto.MemShellGenerateRequest;
import com.reajason.javaweb.boot.dto.MemShellGenerateResponse;
import com.reajason.javaweb.boot.service.GenerationOutcome;
import com.reajason.javaweb.boot.service.MemShellGenerationService;
import com.reajason.javaweb.memshell.MemShellResult;
import org.springframework.web.bind.annotation.*;

/**
 * @author ReaJason
 * @since 2024/12/18
 */
@RestController
@RequestMapping("/api/memshell/generate")
@CrossOrigin("*")
public class MemShellGeneratorController {

    private final MemShellGenerationService generationService;

    public MemShellGeneratorController(MemShellGenerationService generationService) {
        this.generationService = generationService;
    }

    @PostMapping
    public MemShellGenerateResponse generate(@RequestBody MemShellGenerateRequest request) {
        GenerationOutcome<MemShellResult> outcome = generationService.generate(
                request.getShellConfig(),
                request.getInjectorConfig(),
                request.parseShellToolConfig(),
                request.getPacker());
        if (outcome.allPackResults() != null) {
            return new MemShellGenerateResponse(outcome.result(), outcome.allPackResults());
        }
        return new MemShellGenerateResponse(outcome.result(), outcome.packResult());
    }
}
