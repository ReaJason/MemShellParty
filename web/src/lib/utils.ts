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

export function formatBytes(bytes: number) {
  if (bytes === 0) return "0 Bytes";
  if (Number.isNaN(bytes) || !Number.isFinite(bytes)) return "N/A";

  const k = 1024;
  const sizes = ["Bytes", "KB", "MB"]; // Add more units like GB, TB if needed

  if (bytes < k) {
    return `${bytes.toFixed(0)} ${sizes[0]}`; // Bytes, no decimal
  }

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  // Prefer MB if KB value is 1000 or more, or if it's already in MB (i >= 2)
  if (i >= 2 || bytes / k ** 1 >= 1000) {
    const mbValue = Number.parseFloat((bytes / k ** 2).toFixed(2));
    return `${mbValue} ${sizes[2]}`;
  }
  const kbValue = Number.parseFloat((bytes / k ** 1).toFixed(1));
  return `${kbValue} ${sizes[1]}`;
}
