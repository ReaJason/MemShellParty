package com.reajason.javaweb.desktop.memshell.model;

import java.util.ArrayList;
import java.util.List;

public class PackerCategoryModel {
    private String name;
    private final List<PackerEntryModel> packers = new ArrayList<>();

    public PackerCategoryModel() {}
    public PackerCategoryModel(String name) { this.name = name; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public List<PackerEntryModel> getPackers() { return packers; }
}
