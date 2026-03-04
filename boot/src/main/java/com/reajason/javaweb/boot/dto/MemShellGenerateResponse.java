package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.memshell.MemShellResult;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author ReaJason
 * @since 2024/12/18
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MemShellGenerateResponse {
    private MemShellResult memShellResult;
    private String packResult;
}
