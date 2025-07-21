import { TFunction } from "i18next";
import { useCallback } from "react";
import { FieldErrors } from "react-hook-form";
import * as yup from "yup";
import { ShellToolType } from "./shell";

export const formSchema = yup.object({
  server: yup.string().required().min(1),
  serverVersion: yup.string().required().min(1),
  targetJdkVersion: yup.string().optional(),
  debug: yup.boolean().optional(),
  bypassJavaModule: yup.boolean().optional(),
  shellClassName: yup.string().optional(),
  shellTool: yup.string().required().min(1),
  shellType: yup.string().required().min(1),
  urlPattern: yup.string().optional(),
  godzillaPass: yup.string().optional(),
  godzillaKey: yup.string().optional(),
  behinderPass: yup.string().optional(),
  antSwordPass: yup.string().optional(),
  commandParamName: yup.string().optional(),
  implementationClass: yup.string().optional(),
  headerName: yup.string().optional(),
  headerValue: yup.string().optional(),
  injectorClassName: yup.string().optional(),
  packingMethod: yup.string().required().min(1),
  shrink: yup.boolean().optional(),
  shellClassBase64: yup.string().optional(),
  encryptor: yup.string().optional(),
});

interface ValidationResult {
  values: FormSchema;
  errors: FieldErrors<FormSchema>;
}

const urlPatternIsNeeded = (shellType: string) => {
  if (shellType.startsWith("Agent")) {
    return false;
  }
  return (
    shellType.endsWith("Servlet") ||
    shellType.endsWith("ControllerHandler") ||
    shellType === "HandlerMethod" ||
    shellType === "HandlerFunction" ||
    shellType.endsWith("WebSocket")
  );
};

const isInvalidUrl = (urlPattern: string | undefined) =>
  urlPattern === "/" || urlPattern === "/*" || !urlPattern?.startsWith("/") || !urlPattern;

export const useYupValidationResolver = (validationSchema: yup.ObjectSchema<any>, t: TFunction) =>
  useCallback(
    async (data: FormSchema): Promise<ValidationResult> => {
      try {
        const values = (await validationSchema.validate(data, {
          abortEarly: false,
        })) as FormSchema;

        const urlPattern: keyof FormSchema = "urlPattern";
        const shellClassBase64: keyof FormSchema = "shellClassBase64";
        const serverVersion: keyof FormSchema = "serverVersion";
        const errors = {} as any;

        if (urlPatternIsNeeded(values?.shellType) && isInvalidUrl(values?.urlPattern)) {
          errors[urlPattern] = {
            type: "custom",
            message: t("tips.specificUrlPattern"),
          };
        }
        if (values.shellTool === ShellToolType.Custom && !values.shellClassBase64) {
          errors[shellClassBase64] = {
            type: "custom",
            message: t("tips.customShellClass"),
          };
        }
        if (values.server === "TongWeb" && values.shellType === "Valve" && values.serverVersion === "unknown") {
          errors[serverVersion] = {
            type: "custom",
            message: t("tips.serverVersion"),
          };
        }

        return {
          values,
          errors,
        };
      } catch (errors) {
        if (errors instanceof yup.ValidationError) {
          return {
            values: {} as FormSchema,
            errors: errors.inner.reduce(
              (allErrors, currentError) => {
                allErrors[currentError.path as keyof FormSchema] = {
                  type: currentError.type ?? "validation",
                  message: currentError.message,
                };
                return allErrors;
              },
              {} as FieldErrors<FormSchema>,
            ),
          };
        }

        return {
          values: {} as FormSchema,
          errors: {
            server: {
              type: "unknown",
              message: "An unexpected validation error occurred",
            },
          },
        };
      }
    },
    [validationSchema, t],
  );

export type FormSchema = yup.InferType<typeof formSchema>;
