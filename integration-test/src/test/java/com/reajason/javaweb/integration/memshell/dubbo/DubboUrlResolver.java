package com.reajason.javaweb.integration.memshell.dubbo;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

final class DubboUrlResolver {

    private DubboUrlResolver() {
    }

    static List<String> resolveCommandUrls(String loadOutput, String interfaceName, List<String> fallbackUrls) {
        Map<String, String> discoveredByProtocol = new LinkedHashMap<String, String>();
        Pattern pattern = Pattern.compile("(dubbo|hessian|tri)://[^\\s,]*" + Pattern.quote(interfaceName) + "(?:\\?[^\\s,]*)?");
        Matcher matcher = pattern.matcher(loadOutput);
        while (matcher.find()) {
            String candidate = matcher.group();
            discoveredByProtocol.put(protocolOf(candidate), candidate);
        }
        return fallbackUrls.stream()
                .map(fallback -> {
                    String discovered = discoveredByProtocol.get(protocolOf(fallback));
                    return discovered == null ? fallback : rewriteEndpoint(discovered, fallback);
                })
                .collect(Collectors.toList());
    }

    static String protocolOf(String url) {
        int separator = url.indexOf("://");
        return separator < 0 ? url : url.substring(0, separator);
    }

    static String rewriteHost(String url, String host) {
        try {
            URI uri = new URI(url);
            return new URI(
                    uri.getScheme(),
                    uri.getUserInfo(),
                    host,
                    uri.getPort(),
                    uri.getPath(),
                    uri.getQuery(),
                    uri.getFragment()
            ).toString();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("invalid direct url: " + url, e);
        }
    }

    static String rewriteEndpoint(String url, String endpointUrl) {
        try {
            URI uri = new URI(url);
            URI endpoint = new URI(endpointUrl);
            return new URI(
                    uri.getScheme(),
                    uri.getUserInfo(),
                    endpoint.getHost(),
                    endpoint.getPort(),
                    uri.getPath(),
                    uri.getQuery(),
                    uri.getFragment()
            ).toString();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("invalid direct url: " + url + " or " + endpointUrl, e);
        }
    }
}
