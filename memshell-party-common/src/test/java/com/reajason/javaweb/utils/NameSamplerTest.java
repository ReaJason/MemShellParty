package com.reajason.javaweb.utils;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 */
class NameSamplerTest {

    private static final String[] SUFFIXES = {
            "Filter", "Valve", "Listener", "Servlet", "Handler", "Interceptor",
            "Action", "Service", "Controller", "WebSocket", "WebFilter",
            "FilterChain", "ContextValve", "ServletHandler", "FilterManager",
            "ServletContext", "UpgradeHandler", "Customizer", "Agent", "Utils"
    };

    private static final String RESOURCE_DIR = "/com/reajason/javaweb/naming/";

    @Test
    void samplesValidJavaClassNames() {
        for (int i = 0; i < 300; i++) {
            for (String suffix : SUFFIXES) {
                NameSampler.SampledName sampled = NameSampler.sample(suffix);
                assertTrue(sampled.getPackageSegment().matches("[a-z][a-z0-9]*"), sampled.getClassName());
                assertTrue(sampled.getSimpleName().matches("[A-Z][A-Za-z0-9]*"), sampled.getClassName());
                assertTrue(sampled.getSimpleName().endsWith(suffix), sampled.getClassName());
                assertTrue(sampled.getSimpleName().length() <= 64, sampled.getClassName());
                assertFalse(sampled.getSimpleName().contains(suffix + suffix), sampled.getClassName());
            }
        }
    }

    @Test
    void avoidsRepeatedFragmentsWithCompositeSuffixes() {
        for (int i = 0; i < 2000; i++) {
            assertFalse(NameSampler.sample("ContextValve").getSimpleName().contains("ContextContextValve"));
            assertFalse(NameSampler.sample("ServletContext").getSimpleName().contains("ContextServletContext"));
            assertFalse(NameSampler.sample("FilterManager").getSimpleName().contains("FilterFilterManager"));
            assertFalse(NameSampler.sample("WebFilter").getSimpleName().contains("WebWebFilter"));
        }
    }

    @Test
    void classNameCombinesPackageSegmentAndSimpleName() {
        NameSampler.SampledName sampled = NameSampler.sample("Filter");
        assertEquals(sampled.getPackageSegment() + "." + sampled.getSimpleName(), sampled.getClassName());
    }

    @Test
    void wordsComeFromTheSameSemanticDomain() throws IOException {
        Map<String, Set<String>> packageWords = loadWords("package-words.txt");
        Map<String, Set<String>> prefixes = loadWords("class-prefixes.txt");
        Map<String, Set<String>> middles = loadWords("class-middles.txt");

        for (int i = 0; i < 1000; i++) {
            NameSampler.SampledName sampled = NameSampler.sample("Filter");
            String domain = sampled.getDomain();
            String simpleName = sampled.getSimpleName();

            assertTrue(packageWords.get(domain).contains(sampled.getPackageSegment()),
                    domain + " -> " + sampled.getClassName());

            Set<String> allowedPrefixes = new HashSet<>(prefixes.get(domain));
            allowedPrefixes.addAll(prefixes.get("generic"));
            Set<String> allowedMiddles = new HashSet<>(middles.get(domain));
            allowedMiddles.addAll(middles.get("generic"));

            boolean matched = false;
            for (String prefix : allowedPrefixes) {
                if (!simpleName.startsWith(prefix)) {
                    continue;
                }
                String rest = simpleName.substring(prefix.length());
                for (String middle : allowedMiddles) {
                    if (rest.equals(middle + "Filter")) {
                        matched = true;
                        break;
                    }
                }
                if (matched) {
                    break;
                }
            }
            assertTrue(matched, domain + " -> " + sampled.getClassName());
        }
    }

    @Test
    void avoidsSecurityToolingVocabulary() throws IOException {
        String[] forbiddenFragments = {
                "exploit", "payload", "shell", "backdoor", "malware", "trojan",
                "rootkit", "keylog", "stealer", "webshell", "memshell"
        };
        Set<String> forbiddenWords = new HashSet<>(Arrays.asList(
                "poc", "pocs", "cve", "cves", "vuln", "vulns", "vulnerability",
                "attack", "attacks", "hack", "hacks", "hacker", "bypass", "spoof",
                "sniff", "sniffer", "tamper", "evasion", "penetration", "intrusion"
        ));
        for (String resource : new String[]{
                "package-words.txt", "class-prefixes.txt", "class-middles.txt"}) {
            for (Set<String> words : loadWords(resource).values()) {
                for (String word : words) {
                    String lower = word.toLowerCase(Locale.ROOT);
                    assertFalse(forbiddenWords.contains(lower), resource + ": " + word);
                    for (String fragment : forbiddenFragments) {
                        assertFalse(lower.contains(fragment), resource + ": " + word);
                    }
                }
            }
        }
    }

    @Test
    void sampleWordReturnsLowercaseWords() {
        for (int i = 0; i < 200; i++) {
            String word = NameSampler.sampleWord();
            assertTrue(word.matches("[a-z][a-z0-9]*"), word);
            String bounded = NameSampler.sampleWord(5);
            assertTrue(bounded.length() <= 5, bounded);
        }
        assertThrows(IllegalArgumentException.class, () -> NameSampler.sampleWord(1));
    }

    @Test
    void rejectsInvalidSuffix() {
        assertThrows(IllegalArgumentException.class, () -> NameSampler.sample(null));
        assertThrows(IllegalArgumentException.class, () -> NameSampler.sample(""));
        assertThrows(IllegalArgumentException.class, () -> NameSampler.sample("filter"));
        assertThrows(IllegalArgumentException.class, () -> NameSampler.sample("Filter-"));
        assertThrows(IllegalArgumentException.class, () -> NameSampler.sample("Filter$X"));
        String tooLong = String.join("", java.util.Collections.nCopies(59, "A"));
        assertThrows(IllegalArgumentException.class, () -> NameSampler.sample(tooLong));
        assertFalse(NameSampler.isValidSuffix(tooLong));
        assertTrue(NameSampler.isValidSuffix("Filter"));
        assertFalse(NameSampler.isValidSuffix("filter"));
    }

    private static Map<String, Set<String>> loadWords(String resource) throws IOException {
        InputStream inputStream = NameSamplerTest.class.getResourceAsStream(RESOURCE_DIR + resource);
        Map<String, Set<String>> domains = new LinkedHashMap<>();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split(":", 2);
                Set<String> words = domains.computeIfAbsent(parts[0].trim(), key -> new HashSet<>());
                for (String raw : parts[1].split(",")) {
                    String word = raw.trim();
                    if (!word.isEmpty()) {
                        words.add(word);
                    }
                }
            }
        }
        return domains;
    }
}
