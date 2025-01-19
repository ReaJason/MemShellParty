import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function downloadBytes(base64String: string, className?: string, jarName?: string) {
  const byteCharacters = atob(base64String);
  const byteNumbers = new Array(byteCharacters.length);
  for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i);
  }
  const byteArray = new Uint8Array(byteNumbers);

  // Create a Blob from the byte array
  const blob = new Blob([byteArray], { type: className ? "application/java-vm" : "application/java-archive" });

  // Create a download link
  const link = document.createElement("a");
  link.href = window.URL.createObjectURL(blob);
  link.download = className ? `${className.substring(className.lastIndexOf("."))}.class` : `${jarName}.jar`;

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
