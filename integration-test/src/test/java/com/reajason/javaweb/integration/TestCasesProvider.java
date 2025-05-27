package com.reajason.javaweb.integration;

import com.reajason.javaweb.memshell.Packers;
import com.reajason.javaweb.memshell.Server;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
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
                                                 Server server,
                                                 List<String> testShellTypes,
                                                 List<Packers> testPackers,
                                                 List<Triple<String, ShellTool, Packers>> unSupportedCases) {
        return getTestCases(imageName, server, testShellTypes, testPackers, unSupportedCases, null);
    }

    public static Stream<Arguments> getTestCases(String imageName,
                                                 Server server,
                                                 List<String> testShellTypes,
                                                 List<Packers> testPackers,
                                                 List<Triple<String, ShellTool, Packers>> unSupportedCases,
                                                 List<ShellTool> unSupportedShellTools) {
        Set<ShellTool> supportedShellTools = new TreeSet<>(server.getShell().getSupportedShellTools());
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
                    Set<String> supportedShellTypes = server.getShell().getSupportedShellTypes(supportedShellTool);
                    for (String testShellType : testShellTypes) {
                        if (supportedShellTypes.contains(testShellType)) {
                            toolSupportedShellTypes.add(testShellType);
                        }
                    }
                    return toolSupportedShellTypes.stream().flatMap(supportedShellType -> {
                        if (supportedShellType.startsWith(ShellType.AGENT)) {
                            if (!unSupported.contains(supportedShellType + supportedShellTool + Packers.AgentJar)) {
                                return Stream.of(
                                        arguments(imageName, supportedShellType, supportedShellTool, Packers.AgentJar)
                                );
                            }
                            return Stream.empty();
                        } else {
                            return testPackers.stream()
                                    .map(testPacker -> {
                                        if (!unSupported.contains(supportedShellType + supportedShellTool + testPacker)) {
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
                                                 Server server,
                                                 List<String> testShellTypes,
                                                 List<Packers> testPackers) {
        return getTestCases(imageName, server, testShellTypes, testPackers, null);
    }
}
