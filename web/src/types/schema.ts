import * as z from "zod";

export const formSchema = z.object({
  server: z.string().min(1),
  targetJdkVersion: z.optional(z.string()),
  debug: z.optional(z.boolean()),
  bypassJavaModule: z.optional(z.boolean()),
  shellClassName: z.string().optional(),
  shellTool: z.string().min(1),
  shellType: z.string().min(1),
  urlPattern: z.optional(z.string()),
  godzillaPass: z.optional(z.string()),
  godzillaKey: z.optional(z.string()),
  behinderPass: z.optional(z.string()),
  antSwordPass: z.optional(z.string()),
  commandParamName: z.optional(z.string()),
  implementationClass: z.optional(z.string()),
  headerName: z.optional(z.string()),
  headerValue: z.optional(z.string()),
  injectorClassName: z.optional(z.string()),
  packingMethod: z.string().min(1),
  shrink: z.optional(z.boolean()),
  shellClassBase64: z.optional(z.string()),
  encryptor: z.optional(z.string()),
});

export type FormSchema = z.infer<typeof formSchema>;
