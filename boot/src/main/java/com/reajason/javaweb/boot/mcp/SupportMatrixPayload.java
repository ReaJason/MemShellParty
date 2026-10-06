package com.reajason.javaweb.boot.mcp;

import com.reajason.javaweb.boot.vo.CommandConfigVO;
import com.reajason.javaweb.boot.vo.PackerVO;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 能力矩阵。作为 MCP 生成类工具的唯一参数来源，调用方应先查询本结果再构造生成参数。
 *
 * @param servers                  服务端 → 内存马功能 → 受支持的内存马类型
 * @param packers                  顶层打包器及子打包器
 * @param commandConfigs           Command 内存马可用的加密器与实现类
 * @param probeResponseBodyServers ResponseBody 探测马支持的服务端
 * @param probeMethods             合法的 probeMethod 取值
 * @param probeContents            全部的 probeContent 取值
 * @param probeContentsByMethod    各 probeMethod 实际支持的 probeContent 子集——取值按方式分叉，必须查这张表
 * @author ReaJason
 */
public record SupportMatrixPayload(
        Map<String, Map<String, Set<String>>> servers,
        List<PackerVO> packers,
        CommandConfigVO commandConfigs,
        List<String> probeResponseBodyServers,
        List<String> probeMethods,
        List<String> probeContents,
        Map<String, List<String>> probeContentsByMethod) {
}
