package com.reajason.javaweb.packer.spec;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Field metadata for packer config UI.
 */
@Data
public class PackerFieldSchema {
    private String key;
    private PackerFieldType type;
    private boolean required;
    private Object defaultValue;
    private String description;
    private String descriptionI18nKey;
    private List<PackerOptionValue> options = new ArrayList<>();
}
