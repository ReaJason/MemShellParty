package com.reajason.javaweb.integration;

import com.reajason.javaweb.memshell.MemShellRegistry;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.utils.tuple.Triple;
import org.junit.jupiter.params.provider.Arguments;

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
                                                 List<String> testPackers,
                                                 List<Triple<String, String, String>> unSupportedCases) {
        return getTestCases(imageName, server, testShellTypes, testPackers, unSupportedCases, null);
    }

    public static Stream<Arguments> getTestCases(String imageName,
                                                 String server,
                                                 List<String> testShellTypes,
                                                 List<String> testPackers,
                                                 List<Triple<String, String, String>> unSupportedCases,
                                                 List<String> unSupportedShellTools) {
        Set<String> supportedShellTools = new TreeSet<>(MemShellRegistry.getInstance().getServer(server).getSupportedShellTools());
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
                    Set<String> supportedShellTypes = MemShellRegistry.getInstance().getServer(server).getSupportedShellTypes(supportedShellTool);
                    for (String testShellType : testShellTypes) {
                        if (supportedShellTypes.contains(testShellType)) {
                            toolSupportedShellTypes.add(testShellType);
                        }
                    }
                    return toolSupportedShellTypes.stream().flatMap(supportedShellType -> {
                        if (supportedShellType.startsWith(ShellType.AGENT)) {
                            Set<String> agentPackers = testPackers.stream()
                                    .filter(TestCasesProvider::isAgentPacker)
                                    .collect(Collectors.toCollection(LinkedHashSet::new));
                            if (agentPackers.isEmpty()) {
                                agentPackers.add(Packers.AgentJar);
                            }
                            return agentPackers.stream()
                                    .filter(packer -> !unSupported.contains(supportedShellType + supportedShellTool + packer))
                                    .map(packer -> Arguments.arguments(imageName, supportedShellType, supportedShellTool, packer));
                        } else {
                            return testPackers.stream()
                                    .map(testPacker -> {
                                        if (!unSupported.contains(supportedShellType + supportedShellTool + testPacker)
                                                && !isAgentPacker(testPacker)) {
                                            return arguments(imageName, supportedShellType, supportedShellTool, testPacker);
                                        } else {
                                            return null;
                                        }
                                    }).filter(Objects::nonNull);
                        }
                    });
                });
    }

    private static boolean isAgentPacker(String packer) {
        return packer.startsWith(Packers.AgentJar) || Packers.FilelessAgent.equals(packer);
    }

    public static Stream<Arguments> getTestCases(String imageName,
                                                 String server,
                                                 List<String> testShellTypes,
                                                 List<String> testPackers) {
        return getTestCases(imageName, server, testShellTypes, testPackers, null);
    }
}
