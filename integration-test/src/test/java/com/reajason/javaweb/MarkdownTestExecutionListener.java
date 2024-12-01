package com.reajason.javaweb;

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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/1
 */
public class MarkdownTestExecutionListener implements TestExecutionListener {

    private final Map<UniqueId, Instant> timeStamps = new HashMap<>();
    private Instant startTime;
    private final Path markdownPath = Paths.get("build", "test-results", "result.md");
    private final List<String> passedResults = new ArrayList<>();
    private final List<String> failedResults = new ArrayList<>();

    @SneakyThrows
    @Override
    public void testPlanExecutionStarted(TestPlan testPlan) {
        Files.deleteIfExists(markdownPath);
        ArrayList<String> lines = new ArrayList<>();
        lines.add("## Integration Test");
        startTime = Instant.now();
        lines.add("- Started At: " + startTime);
        Files.write(markdownPath, lines, StandardOpenOption.CREATE_NEW);
    }

    @Override
    @SneakyThrows
    public void testPlanExecutionFinished(TestPlan testPlan) {
        List<String> lines = new ArrayList<>();
        Instant endTime = Instant.now();
        lines.add("- Finished At: " + endTime);
        lines.add("- Total Duration: " + Duration.between(startTime, endTime).getSeconds() + " seconds");
        lines.add("");
        lines.add("| **Image Name** | **Shell Type** | **Packer** | **Status**| **Duration(ms)** |");
        lines.add("|----------------|----------------|------------|-----------|------------------|");
        lines.addAll(failedResults);
        lines.addAll(passedResults);
        Files.write(markdownPath, lines, StandardOpenOption.APPEND);
    }

    @Override
    public void executionFinished(TestIdentifier testIdentifier, TestExecutionResult testExecutionResult) {
        if (testIdentifier.isTest()) {
            Instant startTime = timeStamps.get(testIdentifier.getUniqueIdObject());
            if (startTime != null) {
                String[] split = testIdentifier.getDisplayName().split("\\|");
                if (split.length == 3) {
                    if (testExecutionResult.getStatus().equals(TestExecutionResult.Status.SUCCESSFUL)) {
                        passedResults.add("|" + split[0].trim() + "|" + split[1].trim() + "|" + split[2].trim() + "|✔|" + Duration.between(startTime, Instant.now()).toMillis() + "|");
                    } else {
                        failedResults.add("|" + split[0].trim() + "|" + split[1].trim() + "|" + split[2].trim() + "|✘|" + Duration.between(startTime, Instant.now()).toMillis() + "|");
                    }
                }
            }
        }
    }

    @Override
    public void executionStarted(TestIdentifier testIdentifier) {
        if (testIdentifier.isTest()) {
            timeStamps.put(testIdentifier.getUniqueIdObject(), Instant.now());
        }
    }
}
