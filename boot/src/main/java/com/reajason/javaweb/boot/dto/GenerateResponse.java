package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.config.GenerateResult;
import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * @author ReaJason
 * @since 2024/12/18
 */
@Data
@AllArgsConstructor
public class GenerateResponse {
    private GenerateResult generateResult;
    private String packResult;
}
