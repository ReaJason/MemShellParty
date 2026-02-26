package com.reajason.javaweb.packer.spec;

import lombok.Data;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Request-time packer selection and config.
 */
@Data
public class PackerRequestSpec {
    private String name;
    private Map<String, Object> config = new LinkedHashMap<>();
}
