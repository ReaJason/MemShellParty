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
  godzillaHeaderName: z.optional(z.string()),
  godzillaHeaderValue: z.optional(z.string()),
  commandParamName: z.optional(z.string()),
  injectorClassName: z.optional(z.string()),
  packingMethod: z.string().min(1, { message: "请选择打包方式" }),
});

export type FormSchema = z.infer<typeof formSchema>;
