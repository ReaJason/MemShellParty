package com.reajason.javaweb.boot.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BytecodeClassResponse {
    private String className;
    private int size;
    private String classBytesBase64Str;
}
