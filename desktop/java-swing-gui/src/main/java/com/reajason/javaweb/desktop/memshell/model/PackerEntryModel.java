package com.reajason.javaweb.desktop.memshell.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class PackerEntryModel {
    private String categoryName;
    private String name;
    private String outputKind;
    private boolean categoryAnchor;
    private final List<PackerSchemaFieldModel> fields = new ArrayList<>();
    private final Map<String, Object> defaultConfig = new LinkedHashMap<>();

    public String getCategoryName() { return categoryName; }
    public void setCategoryName(String categoryName) { this.categoryName = categoryName; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getOutputKind() { return outputKind; }
    public void setOutputKind(String outputKind) { this.outputKind = outputKind; }
    public boolean isCategoryAnchor() { return categoryAnchor; }
    public void setCategoryAnchor(boolean categoryAnchor) { this.categoryAnchor = categoryAnchor; }
    public List<PackerSchemaFieldModel> getFields() { return fields; }
    public Map<String, Object> getDefaultConfig() { return defaultConfig; }

    public String displayLabel() {
        return categoryName == null || categoryName.equals(name) ? name : categoryName + " / " + name;
    }
}
