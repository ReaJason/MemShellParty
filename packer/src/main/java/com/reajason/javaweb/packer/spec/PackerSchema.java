package com.reajason.javaweb.packer.spec;

import lombok.Data;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Packer config schema metadata.
 */
@Data
public class PackerSchema {
    private List<PackerFieldSchema> fields = new ArrayList<>();
    private Map<String, Object> defaultConfig = new LinkedHashMap<>();

    public static PackerSchema empty() {
        return new PackerSchema();
    }
}
