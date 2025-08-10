import type { TFunction } from "i18next";
import { useCallback } from "react";
import type { FieldErrors } from "react-hook-form";
import * as yup from "yup";
import { ShellToolType } from "./shell";

export const shellFormSchema = yup.object({
  server: yup.string().required().min(1),
  serverVersion: yup.string().required().min(1),
  targetJdkVersion: yup.string().optional(),
  debug: yup.boolean().optional(),
  byPassJavaModule: yup.boolean().optional(),
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
  values: ShellFormSchema;
  errors: FieldErrors<ShellFormSchema>;
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
    async (data: ShellFormSchema): Promise<ValidationResult> => {
      try {
        const values = (await validationSchema.validate(data, {
          abortEarly: false,
        })) as ShellFormSchema;

        const urlPattern: keyof ShellFormSchema = "urlPattern";
        const shellClassBase64: keyof ShellFormSchema = "shellClassBase64";
        const serverVersion: keyof ShellFormSchema = "serverVersion";
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
            values: {} as ShellFormSchema,
            errors: errors.inner.reduce(
              (allErrors, currentError) => {
                allErrors[currentError.path as keyof ShellFormSchema] = {
                  type: currentError.type ?? "validation",
                  message: currentError.message,
                };
                return allErrors;
              },
              {} as FieldErrors<ShellFormSchema>,
            ),
          };
        }

        return {
          values: {} as ShellFormSchema,
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

export type ShellFormSchema = yup.InferType<typeof shellFormSchema>;

export type ProbeFormSchema = yup.InferType<typeof probeFormSchema>;

export const probeFormSchema = yup.object().shape({
  probeMethod: yup.string().required(),
  probeContent: yup.string().required(),
  shellClassName: yup.string().optional(),
  host: yup.string().optional(),
  server: yup.string().optional(),
  reqParamName: yup.string().optional(),
  reqHeaderName: yup.string().optional(),
  seconds: yup.number().optional(),
  sleepServer: yup.string().optional(),
  packingMethod: yup.string().required(),
  targetJdkVersion: yup.string().optional(),
  debug: yup.boolean().optional(),
  byPassJavaModule: yup.boolean().optional(),
  shrink: yup.boolean().optional(),
});

interface ProbeValidationResult {
  values: ProbeFormSchema;
  errors: FieldErrors<ProbeFormSchema>;
}

export const useYupValidationProbeResolver = (validationSchema: yup.ObjectSchema<any>, t: TFunction) =>
  useCallback(
    async (data: ProbeFormSchema): Promise<ProbeValidationResult> => {
      try {
        const values = (await validationSchema.validate(data, {
          abortEarly: false,
        })) as ProbeFormSchema;

        const host: keyof ProbeFormSchema = "host";
        const errors = {} as any;

        if (values.probeMethod === "DNSLog" && !values.host) {
          errors[host] = {
            type: "custom",
            message: t("tips.customShellClass"),
          };
        }
        return {
          values,
          errors,
        };
      } catch (errors) {
        console.log(errors)
        if (errors instanceof yup.ValidationError) {
          return {
            values: {} as ProbeFormSchema,
            errors: errors.inner.reduce(
              (allErrors, currentError) => {
                allErrors[currentError.path as keyof ProbeFormSchema] = {
                  type: currentError.type ?? "validation",
                  message: currentError.message,
                };
                console.log(allErrors)
                return allErrors;
              },
              {} as FieldErrors<ProbeFormSchema>,
            ),
          };
        }

        return {
          values: {} as ProbeFormSchema,
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