package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.packer.spec.PackerRequestSpec;
import lombok.Data;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Packer selection request payload.
 */
@Data
public class PackerRequestSpecDTO {
    private String name;
    private Map<String, Object> config = new LinkedHashMap<>();

    public PackerRequestSpec toPackerRequestSpec() {
        PackerRequestSpec spec = new PackerRequestSpec();
        spec.setName(name);
        if (config != null) {
            spec.setConfig(config);
        }
        return spec;
    }
}
