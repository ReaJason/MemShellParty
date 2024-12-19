import { type ClassValue, clsx } from "clsx";
import { toast } from "sonner";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function downloadJavaClass(base64String?: string, className?: string) {
  if (!base64String || !className) {
    toast.warning("内存马字节码为空，无法下载, 请先生成内存马");
    return;
  }
  const byteCharacters = atob(base64String);
  const byteNumbers = new Array(byteCharacters.length);
  for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i);
  }
  const byteArray = new Uint8Array(byteNumbers);

  // Create a Blob from the byte array
  const blob = new Blob([byteArray], { type: "application/java-vm" });

  // Create a download link
  const link = document.createElement("a");
  link.href = window.URL.createObjectURL(blob);
  link.download = `${className.substring(className.lastIndexOf("."))}.class`;

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
