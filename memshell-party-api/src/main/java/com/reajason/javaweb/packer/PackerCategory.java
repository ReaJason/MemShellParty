package com.reajason.javaweb.packer;

import lombok.Getter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 打包器两级展示目录：分类（{@link PackerMeta#parent()} 分组名）及其子变体，
 * 序列化为 {name, children}。分类本身不一定对应已注册的 packer。
 *
 * @author ReaJason
 * @since 2026/10/12
 */
@Getter
public class PackerCategory {
    private final String name;
    private final List<String> children;

    public PackerCategory(String name, List<String> children) {
        this.name = name;
        this.children = children == null
                ? Collections.<String>emptyList()
                : Collections.unmodifiableList(new ArrayList<String>(children));
    }

    public boolean hasChildren() {
        return !children.isEmpty();
    }
}
