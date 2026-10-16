package com.reajason.javaweb.packer;


import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author ReaJason
 * @since 2025/1/26
 */
public interface AggregatePacker extends Packer {

    /**
     * 聚合打包当前所有分类下的 payload
     *
     * @param config 生成结果
     * @return key - 打包名称，value - 打包 payload
     */
    default Map<String, String> packAll(ClassPackerConfig config) {
        return Packers.getPackersWithParent(this.getClass()).stream().collect(Collectors.toMap(
                Enum::name,
                packers -> {
                    try {
                        return packers.getInstance().pack(config);
                    } catch (Exception e) {
                        return e.getMessage();
                    }
                },
                (existing, replacement) -> existing,
                LinkedHashMap::new
        ));
    }

    /**
     * 将第一个 sub packer 作为默认输出
     *
     * @param config 生成的内存马信息
     * @return payload
     */
    @Override
    default String pack(ClassPackerConfig config) {
        List<Packers> packersWithParent = Packers.getPackersWithParent(this.getClass());
        if (packersWithParent.isEmpty()) {
            return null;
        }
        return packersWithParent.get(0).getInstance().pack(config);
    }
}
