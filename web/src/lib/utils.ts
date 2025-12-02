import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function downloadContent(
  content: Blob,
  fileName: string,
  fileExtension: string,
) {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(content);
  link.download = `${fileName}${fileExtension}`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

export function base64ToBytes(base64String: string) {
  const byteCharacters = atob(base64String);
  const byteNumbers = new Array(byteCharacters.length);
  for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i);
  }
  return new Uint8Array(byteNumbers);
}

export function downloadBytes(
  base64String: string,
  className?: string,
  jarName?: string,
) {
  const byteArray = base64ToBytes(base64String);
  const blob = new Blob([byteArray], {
    type: className ? "application/java-vm" : "application/java-archive",
  });

  const link = document.createElement("a");
  link.href = window.URL.createObjectURL(blob);
  link.download = className
    ? `${className.substring(className.lastIndexOf("."))}.class`
    : `${jarName}.jar`;

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

export function formatBytes(bytes: number) {
  if (bytes === 0) return "0 Bytes";
  if (Number.isNaN(bytes) || !Number.isFinite(bytes)) return "N/A";

  const k = 1024;
  const sizes = ["Bytes", "KB", "MB"];

  if (bytes < k) {
    return `${bytes.toFixed(0)} ${sizes[0]}`;
  }

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  if (i >= 2 || bytes / k ** 1 >= 1000) {
    const mbValue = Number.parseFloat((bytes / k ** 2).toFixed(2));
    return `${mbValue} ${sizes[2]}`;
  }
  const kbValue = Number.parseFloat((bytes / k ** 1).toFixed(1));
  return `${kbValue} ${sizes[1]}`;
}

export function shouldHidden(shellType: string | undefined) {
  if (shellType === undefined) {
    return false;
  }
  return (
    shellType.endsWith("Listener") ||
    shellType.endsWith("Valve") ||
    shellType.startsWith("Agent") ||
    shellType.endsWith("Interceptor") ||
    shellType.endsWith("Handler") ||
    shellType.endsWith("WebFilter") ||
    shellType === "Customizer"
  );
}
