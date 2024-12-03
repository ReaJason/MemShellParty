package com.reajason.javaweb;

import lombok.Builder;
import lombok.Data;
import lombok.SneakyThrows;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.UniqueId;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * @author ReaJason
 * @since 2024/12/1
 */
public class MarkdownTestExecutionListener implements TestExecutionListener {
    @Data
    @Builder
    static class TestCase {
        private String imageName;
        private String shellType;
        private String packer;
        private Duration duration;
        private TestExecutionResult.Status status;
    }

    private final Map<UniqueId, Instant> timeStamps = new ConcurrentHashMap<>();
    private final Map<String, List<TestCase>> testCases = new ConcurrentHashMap<>();
    private Instant startTime;
    private final Path markdownPath = Paths.get("build", "test-results", "report.md");
    private final AtomicLong totalCount = new AtomicLong(0);
    private final AtomicLong successCount = new AtomicLong(0);

    @SneakyThrows
    @Override
    public void testPlanExecutionStarted(TestPlan testPlan) {
        Files.deleteIfExists(markdownPath);
        ArrayList<String> lines = new ArrayList<>();
        lines.add("## Integration Test");
        startTime = Instant.now();
        lines.add("- Started: " + startTime);
        Files.write(markdownPath, lines, StandardOpenOption.CREATE_NEW);
    }

    @Override
    @SneakyThrows
    public void testPlanExecutionFinished(TestPlan testPlan) {
        List<String> lines = new ArrayList<>();
        Instant endTime = Instant.now();
        lines.add("- Finished: " + endTime);
        Duration duration = Duration.between(startTime, endTime);
        lines.add("- Total Duration: " + getDuration(duration));
        lines.add(String.format("- Total Cases: %d/%d, %d failed", successCount.get(), totalCount.get(), totalCount.get() - successCount.get()));
        lines.add("");

        for (Map.Entry<String, List<TestCase>> entry : testCases.entrySet()) {
            lines.add(String.format("### %s", entry.getKey()));
            lines.add("|**Shell Type** | **Packer** | **Status**| **Duration(ms)** |");
            lines.add("|---------------|------------|-----------|------------------|");
            List<TestCase> value = entry.getValue().stream().sorted((tc1, tc2) -> {
                if (tc1.getStatus() == tc2.getStatus()) {
                    return 0;
                }
                return tc1.getStatus() == TestExecutionResult.Status.FAILED ? -1 : 1;
            }).collect(Collectors.toList());
            for (TestCase testCase : value) {
                String status = testCase.getStatus().equals(TestExecutionResult.Status.SUCCESSFUL) ? "✔" : "✘";
                lines.add("|" + testCase.getShellType() + "|" + testCase.getPacker() + "|" + status + "|" + testCase.getDuration().toMillis() + "|");
            }
        }

        Files.write(markdownPath, lines, StandardOpenOption.APPEND);
    }

    private String getDuration(Duration duration) {
        long totalSeconds = duration.getSeconds();
        long minutes = totalSeconds / 60;
        long seconds = totalSeconds % 60;
        if (totalSeconds < 60) {
            return String.format("%d seconds", totalSeconds);
        } else {
            return String.format("%d minutes and %d seconds", minutes, seconds);
        }
    }

    @Override
    public void executionFinished(TestIdentifier testIdentifier, TestExecutionResult testExecutionResult) {
        if (!testIdentifier.isTest()) {
            return;
        }
        Instant startTime = timeStamps.get(testIdentifier.getUniqueIdObject());
        if (startTime == null) {
            return;
        }
        String[] split = testIdentifier.getDisplayName().split("\\|");
        if (split.length == 3) {
            String imageName = split[0].trim();
            String shellType = split[1].trim();
            String packer = split[2].trim();
            List<TestCase> cases = testCases.getOrDefault(imageName, new ArrayList<>());
            cases.add(TestCase.builder()
                    .imageName(imageName)
                    .shellType(shellType)
                    .packer(packer)
                    .duration(Duration.between(startTime, Instant.now()))
                    .status(testExecutionResult.getStatus())
                    .build());
            testCases.put(imageName, cases);
            if (testExecutionResult.getStatus().equals(TestExecutionResult.Status.SUCCESSFUL)) {
                successCount.incrementAndGet();
            }
        }
    }

    @Override
    public void executionStarted(TestIdentifier testIdentifier) {
        if (testIdentifier.isTest()) {
            totalCount.incrementAndGet();
            timeStamps.put(testIdentifier.getUniqueIdObject(), Instant.now());
        }
    }
}
