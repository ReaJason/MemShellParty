package com.reajason.javaweb.memshell.packer.spel;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONWriter;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.AggregatePacker;
import com.reajason.javaweb.memshell.packer.Packers;
import org.junit.jupiter.api.Test;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2025/1/26
 */
class SpELPackerTest {

    @Test
    void pack() {
        GenerateResult generateResult = GenerateResult.builder()
                .injectorClassName("name")
                .injectorBytes("name".getBytes()).build();
        AggregatePacker spELPacker = (AggregatePacker) Packers.SpEL.getInstance();
        Map<String, String> stringStringMap = spELPacker.packAll(generateResult);
        System.out.println(JSON.toJSONString(stringStringMap, JSONWriter.Feature.PrettyFormat));
    }
}