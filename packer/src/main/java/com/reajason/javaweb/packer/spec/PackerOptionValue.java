package com.reajason.javaweb.packer.spec;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Enum option metadata for UI rendering.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PackerOptionValue {
    private String value;
    private String label;
}
