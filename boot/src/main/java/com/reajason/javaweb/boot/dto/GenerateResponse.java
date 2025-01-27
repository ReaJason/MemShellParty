package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.memshell.config.GenerateResult;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/18
 */
@Data
@NoArgsConstructor
public class GenerateResponse {
    private GenerateResult generateResult;
    private String packResult;
    private Map<String, String> allPackResults;

    public GenerateResponse(GenerateResult generateResult, String packResult) {
        this.generateResult = generateResult;
        this.packResult = packResult;
    }

    public GenerateResponse(GenerateResult generateResult, Map<String, String> allPackResults) {
        this.allPackResults = allPackResults;
        this.generateResult = generateResult;
    }
}
