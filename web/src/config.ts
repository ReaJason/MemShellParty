import * as yup from "yup";

const EnvSchema = yup.object({
  API_URL: yup.string().optional(),
  BASE_PATH: yup.string().optional(),
  MODE: yup.string().required(),
});

type EnvSchema = yup.InferType<typeof EnvSchema>;
function safeParseYup<T>(schema: yup.ObjectSchema<any>, data: unknown) {
  try {
    const validatedData = schema.validateSync(data, {
      abortEarly: false,
      stripUnknown: true,
    });

    return {
      success: true as const,
      data: validatedData as T,
      error: undefined,
    };
  } catch (error) {
    if (error instanceof yup.ValidationError) {
      return {
        success: false as const,
        data: undefined,
        error: {
          issues: error.inner.map((err) => ({
            path: err.path?.split(".") || [],
            message: err.message,
            code: err.type ?? "validation_error",
          })),
          message: error.message,
        },
      };
    }

    return {
      success: false as const,
      data: undefined,
      error: {
        issues: [],
        message: "Unknown validation error",
      },
    };
  }
}

const createEnv = () => {
  // @ts-ignore
  const envVars = Object.entries(import.meta.env).reduce<Record<string, string>>((acc, curr) => {
    const [key, value] = curr;
    if (typeof value === "string") {
      if (key.startsWith("VITE_APP_")) {
        acc[key.replace("VITE_APP_", "")] = value;
      }
      if (key === "MODE") {
        acc[key] = value;
      }
    }
    return acc;
  }, {});
  const parsedEnv = safeParseYup<EnvSchema>(EnvSchema, envVars);
  if (!parsedEnv.success) {
    throw new Error(
      `Invalid env provided.
The following variables are missing or invalid:
${parsedEnv.error.issues.map(({ path, message }) => `- ${path}: ${message}`).join("\n")}
`,
    );
  }
  return parsedEnv.data;
};

export const env = createEnv();
