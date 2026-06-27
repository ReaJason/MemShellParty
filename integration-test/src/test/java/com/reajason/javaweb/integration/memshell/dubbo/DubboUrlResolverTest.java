package com.reajason.javaweb.integration.memshell.dubbo;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;

class DubboUrlResolverTest {

    @Test
    void discoveredUrlsOverrideFallbackByProtocolAndRewriteHost() {
        String interfaceName = "org.example.ICommandService";
        String loadOutput = "ok dubbo://x.x.x.x:20880/" + interfaceName + "?side=provider, "
                + "hessian://10.1.2.3:28080/" + interfaceName;

        List<String> resolved = DubboUrlResolver.resolveCommandUrls(
                loadOutput,
                interfaceName,
                List.of(
                        "dubbo://127.0.0.1:1111/" + interfaceName,
                        "hessian://127.0.0.1:2222/" + interfaceName,
                        "tri://127.0.0.1:3333/" + interfaceName
                )
        );

        assertThat(resolved, contains(
                "dubbo://127.0.0.1:1111/" + interfaceName + "?side=provider",
                "hessian://127.0.0.1:2222/" + interfaceName,
                "tri://127.0.0.1:3333/" + interfaceName
        ));
    }
}
