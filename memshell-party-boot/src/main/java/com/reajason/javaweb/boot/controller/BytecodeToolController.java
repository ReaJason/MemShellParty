package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.api.ErrorResponse;
import com.reajason.javaweb.boot.dto.BytecodeClassResponse;
import com.reajason.javaweb.boot.dto.BytecodeTransformRequest;
import com.reajason.javaweb.boot.dto.BytecodeTransformResponse;
import com.reajason.javaweb.boot.service.BytecodeTransformService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/bytecode")
@CrossOrigin("*")
public class BytecodeToolController {
    private final BytecodeTransformService transformService;

    public BytecodeToolController(BytecodeTransformService transformService) {
        this.transformService = transformService;
    }

    @PostMapping(value = "/decode", consumes = MediaType.TEXT_PLAIN_VALUE)
    public BytecodeClassResponse decode(@RequestBody String classBase64) {
        return transformService.decode(classBase64);
    }

    @PostMapping("/transform")
    public BytecodeTransformResponse transform(@RequestBody BytecodeTransformRequest request) {
        return transformService.transform(request);
    }

    @ExceptionHandler({IllegalArgumentException.class, UnsupportedOperationException.class})
    public ResponseEntity<ErrorResponse> handleInvalidInput(RuntimeException exception) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse(exception.getMessage()));
    }
}
