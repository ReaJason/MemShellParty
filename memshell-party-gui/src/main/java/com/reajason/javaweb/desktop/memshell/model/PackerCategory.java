package com.reajason.javaweb.desktop.memshell.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 打包器两级树节点：分类（根 packer）及其子变体。
 */
public class PackerCategory {
    private final String name;
    private final List<String> children;

    public PackerCategory(String name, List<String> children) {
        this.name = name;
        this.children = children == null
                ? Collections.<String>emptyList()
                : Collections.unmodifiableList(new ArrayList<String>(children));
    }

    public String getName() {
        return name;
    }

    public List<String> getChildren() {
        return children;
    }

    public boolean hasChildren() {
        return !children.isEmpty();
    }
}
