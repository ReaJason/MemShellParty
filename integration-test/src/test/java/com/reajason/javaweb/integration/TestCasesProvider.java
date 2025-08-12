package com.reajason.javaweb.integration;

import com.reajason.javaweb.memshell.ServerFactory;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import org.junit.jupiter.params.provider.Arguments;
import org.testcontainers.shaded.org.apache.commons.lang3.tuple.Triple;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2025/2/23
 */
public class TestCasesProvider {

    public static Stream<Arguments> getTestCases(String imageName,
                                                 String server,
                                                 List<String> testShellTypes,
                                                 List<Packers> testPackers,
                                                 List<Triple<String, ShellTool, Packers>> unSupportedCases) {
        return getTestCases(imageName, server, testShellTypes, testPackers, unSupportedCases, null);
    }

    public static Stream<Arguments> getTestCases(String imageName,
                                                 String server,
                                                 List<String> testShellTypes,
                                                 List<Packers> testPackers,
                                                 List<Triple<String, ShellTool, Packers>> unSupportedCases,
                                                 List<ShellTool> unSupportedShellTools) {
        Set<ShellTool> supportedShellTools = new TreeSet<>(ServerFactory.getServer(server).getSupportedShellTools());
        if (unSupportedShellTools != null) {
            unSupportedShellTools.forEach(supportedShellTools::remove);
        }
        Set<String> unSupported = unSupportedCases == null ?
                Collections.emptySet() :
                unSupportedCases
                        .stream()
                        .map(i -> i.getLeft() + i.getMiddle() + i.getRight())
                        .collect(Collectors.toSet());
        return supportedShellTools.stream()
                .flatMap(supportedShellTool -> {
                    List<String> toolSupportedShellTypes = new ArrayList<>();
                    Set<String> supportedShellTypes = ServerFactory.getServer(server).getSupportedShellTypes(supportedShellTool);
                    for (String testShellType : testShellTypes) {
                        if (supportedShellTypes.contains(testShellType)) {
                            toolSupportedShellTypes.add(testShellType);
                        }
                    }
                    return toolSupportedShellTypes.stream().flatMap(supportedShellType -> {
                        if (supportedShellType.startsWith(ShellType.AGENT)) {
                            if (!unSupported.contains(supportedShellType + supportedShellTool + Packers.AgentJar)) {
                                Set<Packers> agentJarPackers = testPackers.stream()
                                        .filter(packer -> packer.name().startsWith("AgentJar")).collect(Collectors.toSet());
                                if (!agentJarPackers.isEmpty()) {
                                    return agentJarPackers.stream()
                                            .map(packer -> Arguments.arguments(imageName, supportedShellType, supportedShellTool, packer));
                                } else {
                                    return Stream.of(arguments(imageName, supportedShellType, supportedShellTool, Packers.AgentJar));
                                }
                            }
                            return Stream.empty();
                        } else {
                            return testPackers.stream()
                                    .map(testPacker -> {
                                        if (!unSupported.contains(supportedShellType + supportedShellTool + testPacker)
                                                && !testPacker.name().startsWith("AgentJar")) {
                                            return arguments(imageName, supportedShellType, supportedShellTool, testPacker);
                                        } else {
                                            return null;
                                        }
                                    }).filter(Objects::nonNull);
                        }
                    });
                });
    }

    public static Stream<Arguments> getTestCases(String imageName,
                                                 String server,
                                                 List<String> testShellTypes,
                                                 List<Packers> testPackers) {
        return getTestCases(imageName, server, testShellTypes, testPackers, null);
    }
}
