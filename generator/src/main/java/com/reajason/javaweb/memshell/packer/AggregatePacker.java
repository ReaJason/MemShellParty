package com.reajason.javaweb.memshell.packer;

import com.reajason.javaweb.memshell.config.GenerateResult;

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
     * @param generateResult 生成结果
     * @return key -> 打包名称， value -> 打包 payload
     */
    default Map<String, String> packAll(GenerateResult generateResult) {
        return Packers.getPackersWithParent(this.getClass()).stream().collect(Collectors.toMap(
                Enum::name,
                packers -> packers.getInstance().pack(generateResult),
                (existing, replacement) -> existing,
                LinkedHashMap::new
        ));
    }

    /**
     * 将第一个 sub packer 作为默认输出
     *
     * @param generateResult 生成的内存马信息
     * @return payload
     */
    @Override
    default String pack(GenerateResult generateResult) {
        List<Packers> packersWithParent = Packers.getPackersWithParent(this.getClass());
        if (packersWithParent.isEmpty()) {
            return null;
        }
        return packersWithParent.get(0).getInstance().pack(generateResult);
    }
}
