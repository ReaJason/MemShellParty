package com.reajason.javaweb.packer;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Shared conversion helper for packer custom config.
 */
final class PackerConfigConverter {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private PackerConfigConverter() {
    }

    static <R> R convert(Object customConfig, Class<R> clazz) {
        if (customConfig == null) {
            return null;
        }
        if (clazz.isInstance(customConfig)) {
            return clazz.cast(customConfig);
        }
        try {
            return OBJECT_MAPPER.convertValue(customConfig, clazz);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid customConfig for " + clazz.getSimpleName() + ": " + e.getMessage(), e);
        }
    }
}
