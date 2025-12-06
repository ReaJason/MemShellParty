import type { TFunction } from "i18next";
import { useCallback } from "react";
import type { FieldErrors, ResolverResult } from "react-hook-form";
import * as yup from "yup";
import { ShellToolType } from "./memshell";

export const memShellFormSchema = yup.object({
  server: yup.string().required().min(1),
  serverVersion: yup.string().required().min(1),
  targetJdkVersion: yup.string().optional(),
  debug: yup.boolean().optional(),
  byPassJavaModule: yup.boolean().optional(),
  staticInitialize: yup.boolean().optional(),
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
  lambdaSuffix: yup.boolean().optional(),
  probe: yup.boolean().optional(),
  shellClassBase64: yup.string().optional(),
  encryptor: yup.string().optional(),
});

type ValidationResult = ResolverResult<MemShellFormSchema>;

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
  urlPattern === "/" ||
  urlPattern === "/*" ||
  !urlPattern?.startsWith("/") ||
  !urlPattern;

export const useYupValidationResolver = (
  validationSchema: yup.ObjectSchema<any>,
  t: TFunction,
) =>
  useCallback(
    async (
      data: MemShellFormSchema,
      _context: any,
    ): Promise<ValidationResult> => {
      try {
        const values = (await validationSchema.validate(data, {
          abortEarly: false,
        })) as MemShellFormSchema;

        const urlPattern: keyof MemShellFormSchema = "urlPattern";
        const shellClassBase64: keyof MemShellFormSchema = "shellClassBase64";
        const serverVersion: keyof MemShellFormSchema = "serverVersion";
        const errors = {} as any;

        if (
          urlPatternIsNeeded(values?.shellType) &&
          isInvalidUrl(values?.urlPattern)
        ) {
          errors[urlPattern] = {
            type: "custom",
            message: t("memshell:tips.specificUrlPattern"),
          };
        }
        if (
          values.shellTool === ShellToolType.Custom &&
          !values.shellClassBase64
        ) {
          errors[shellClassBase64] = {
            type: "custom",
            message: t("memshell:tips.customShellClass"),
          };
        }
        if (
          values.server === "TongWeb" &&
          values.shellType === "Valve" &&
          values.serverVersion === "unknown"
        ) {
          errors[serverVersion] = {
            type: "custom",
            message: t("memshell:tips.serverVersion"),
          };
        }

        if (
          values.server === "Jetty" &&
          (values.shellType === "Handler" ||
            values.shellType === "JakartaHandler") &&
          values.serverVersion === "unknown"
        ) {
          errors[serverVersion] = {
            type: "custom",
            message: t("memshell:tips.serverVersion"),
          };
        }

        return {
          values,
          errors,
        };
      } catch (errors) {
        if (errors instanceof yup.ValidationError) {
          return {
            values: {},
            errors: errors.inner.reduce(
              (allErrors, currentError) => {
                allErrors[currentError.path as keyof MemShellFormSchema] = {
                  type: currentError.type ?? "validation",
                  message: currentError.message,
                };
                return allErrors;
              },
              {} as FieldErrors<MemShellFormSchema>,
            ),
          };
        }

        return {
          values: {},
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

export type MemShellFormSchema = yup.InferType<typeof memShellFormSchema>;

export type ProbeShellFormSchema = yup.InferType<typeof probeShellFormSchema>;

export const probeShellFormSchema = yup.object().shape({
  probeMethod: yup.string().required(),
  probeContent: yup.string().required(),
  shellClassName: yup.string().optional(),
  host: yup.string().optional(),
  server: yup.string().optional(),
  reqParamName: yup.string().optional(),
  seconds: yup.number().optional(),
  sleepServer: yup.string().optional(),
  packingMethod: yup.string().required(),
  targetJdkVersion: yup.string().optional(),
  debug: yup.boolean().optional(),
  byPassJavaModule: yup.boolean().optional(),
  shrink: yup.boolean().optional(),
  staticInitialize: yup.boolean().optional(),
  lambdaSuffix: yup.boolean().optional(),
});

type ProbeValidationResult = ResolverResult<ProbeShellFormSchema>;

export const useYupValidationProbeResolver = (
  validationSchema: yup.ObjectSchema<any>,
  t: TFunction,
) =>
  useCallback(
    async (
      data: ProbeShellFormSchema,
      _context: any,
    ): Promise<ProbeValidationResult> => {
      try {
        const values = (await validationSchema.validate(data, {
          abortEarly: false,
        })) as ProbeShellFormSchema;

        const host: keyof ProbeShellFormSchema = "host";
        const reqParamName: keyof ProbeShellFormSchema = "reqParamName";
        const errors = {} as any;

        if (values.probeMethod === "DNSLog" && !values.host) {
          errors[host] = {
            type: "custom",
            message: t("probeshell:tips.dnslog.host.required"),
          };
        }

        if (values.probeMethod === "ResponseBody" && !values.reqParamName) {
          errors[reqParamName] = {
            type: "custom",
            message: t("probeshell:tips.response.reqParamName.required"),
          };
        }
        return {
          values,
          errors,
        };
      } catch (errors) {
        if (errors instanceof yup.ValidationError) {
          return {
            values: {},
            errors: errors.inner.reduce(
              (allErrors, currentError) => {
                allErrors[currentError.path as keyof ProbeShellFormSchema] = {
                  type: currentError.type ?? "validation",
                  message: currentError.message,
                };
                console.log(allErrors);
                return allErrors;
              },
              {} as FieldErrors<ProbeShellFormSchema>,
            ),
          };
        }

        return {
          values: {},
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
