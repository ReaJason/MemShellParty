package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.memshell.MemShellResult;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author ReaJason
 * @since 2024/12/18
 */
@Data
@NoArgsConstructor
public class MemShellGenerateResponse {
    private MemShellResult memShellResult;
    private String packResult;

    public MemShellGenerateResponse(MemShellResult memShellResult, String packResult) {
        this.memShellResult = memShellResult;
        this.packResult = packResult;
    }
}
