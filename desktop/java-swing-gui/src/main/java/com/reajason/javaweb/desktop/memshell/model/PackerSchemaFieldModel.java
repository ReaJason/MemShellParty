package com.reajason.javaweb.desktop.memshell.model;

import java.util.ArrayList;
import java.util.List;

public class PackerSchemaFieldModel {
    public static class Option {
        private String value;
        private String label;

        public Option() {}
        public Option(String value, String label) {
            this.value = value;
            this.label = label;
        }
        public String getValue() { return value; }
        public void setValue(String value) { this.value = value; }
        public String getLabel() { return label; }
        public void setLabel(String label) { this.label = label; }
    }

    private String key;
    private String type;
    private boolean required;
    private Object defaultValue;
    private String description;
    private String descriptionI18nKey;
    private final List<Option> options = new ArrayList<>();

    public String getKey() { return key; }
    public void setKey(String key) { this.key = key; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public boolean isRequired() { return required; }
    public void setRequired(boolean required) { this.required = required; }
    public Object getDefaultValue() { return defaultValue; }
    public void setDefaultValue(Object defaultValue) { this.defaultValue = defaultValue; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getDescriptionI18nKey() { return descriptionI18nKey; }
    public void setDescriptionI18nKey(String descriptionI18nKey) { this.descriptionI18nKey = descriptionI18nKey; }
    public List<Option> getOptions() { return options; }
}
