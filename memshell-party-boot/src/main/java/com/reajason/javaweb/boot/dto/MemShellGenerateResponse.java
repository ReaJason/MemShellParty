package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.memshell.MemShellResult;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/18
 */
@Data
@NoArgsConstructor
public class MemShellGenerateResponse {
    private MemShellResult memShellResult;
    private String packResult;
    private Map<String, String> allPackResults;

    public MemShellGenerateResponse(MemShellResult memShellResult, String packResult) {
        this.memShellResult = memShellResult;
        this.packResult = packResult;
    }

    public MemShellGenerateResponse(MemShellResult memShellResult, Map<String, String> allPackResults) {
        this.allPackResults = allPackResults;
        this.memShellResult = memShellResult;
    }
}
