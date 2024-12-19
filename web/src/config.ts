import * as z from "zod";

const EnvSchema = z.object({
  API_URL: z.optional(z.string()),
});

const createEnv = () => {
  // @ts-ignore
  const envVars = Object.entries(import.meta.env).reduce<Record<string, string>>((acc, curr) => {
    const [key, value] = curr;
    if (key.startsWith("VITE_APP_")) {
      if (typeof value === "string") {
        acc[key.replace("VITE_APP_", "")] = value;
      }
    }
    return acc;
  }, {});
  const parsedEnv = EnvSchema.safeParse(envVars);
  if (!parsedEnv.success) {
    throw new Error(
      `Invalid env provided.
The following variables are missing or invalid:
${Object.entries(parsedEnv.error.flatten().fieldErrors)
  .map(([k, v]) => `- ${k}: ${v}`)
  .join("\n")}
`,
    );
  }
  return parsedEnv.data;
};

export const env = createEnv();
