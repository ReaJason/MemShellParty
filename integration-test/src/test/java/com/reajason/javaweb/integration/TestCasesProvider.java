package com.reajason.javaweb.integration;

import com.reajason.javaweb.memshell.Packers;
import com.reajason.javaweb.memshell.Server;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import org.junit.jupiter.params.provider.Arguments;
import org.testcontainers.shaded.org.apache.commons.lang3.tuple.Triple;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2025/2/23
 */
public class TestCasesProvider {

    public static Stream<Arguments> getTestCases(String imageName, Server server, Set<String> testShellTypes, Set<Packers> testPackers, Set<Triple<String, ShellTool, Packers>> unSupportedCases) {
        return getTestCases(imageName, server, testShellTypes, testPackers, unSupportedCases, null);
    }

    public static Stream<Arguments> getTestCases(String imageName, Server server, Set<String> testShellTypes, Set<Packers> testPackers, Set<Triple<String, ShellTool, Packers>> unSupportedCases, Set<ShellTool> unSupportedShellTools) {
        Set<ShellTool> supportedShellTools = new HashSet<>(server.getShell().getSupportedShellTools());
        if (unSupportedShellTools != null) {
            supportedShellTools.removeAll(unSupportedShellTools);
        }
        Set<String> unSupported = unSupportedCases == null ? Collections.emptySet() : unSupportedCases.stream().map(i -> i.getLeft() + i.getMiddle() + i.getRight()).collect(Collectors.toSet());
        return supportedShellTools.stream()
                .flatMap(supportedShellTool -> {
                    Set<String> toolSupportedShellTypes = new HashSet<>(server.getShell().getSupportedShellTypes(supportedShellTool));
                    toolSupportedShellTypes.retainAll(testShellTypes);
                    return toolSupportedShellTypes.stream().flatMap(supportedShellType -> {
                        if (supportedShellType.startsWith(ShellType.AGENT)) {
                            if (!unSupported.contains(supportedShellType + supportedShellTool + Packers.AgentJar)) {
                                return Stream.of(arguments(imageName, supportedShellType, supportedShellTool, Packers.AgentJar));
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

    public static Stream<Arguments> getTestCases(String imageName, Server server, Set<String> testShellTypes, Set<Packers> testPackers) {
        return getTestCases(imageName, server, testShellTypes, testPackers, null);
    }
}
