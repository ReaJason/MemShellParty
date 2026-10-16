package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.dto.MemShellGenerateRequest;
import com.reajason.javaweb.boot.dto.MemShellGenerateResponse;
import com.reajason.javaweb.boot.service.GenerationService;
import org.springframework.web.bind.annotation.*;

/**
 * @author ReaJason
 * @since 2024/12/18
 */
@RestController
@RequestMapping("/api/memshell/generate")
@CrossOrigin("*")
public class MemShellGeneratorController {

    private final GenerationService generationService;

    public MemShellGeneratorController(GenerationService generationService) {
        this.generationService = generationService;
    }

    @PostMapping
    public MemShellGenerateResponse generate(@RequestBody MemShellGenerateRequest request) {
        return generationService.generateMemShell(request);
    }
}
