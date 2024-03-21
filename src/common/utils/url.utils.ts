/**
 * Allows to check if a URL is https
 * @param url The URL to check
 * @returns boolean that indicate if the provided URL is https
 */
export function isHttps(url: string) {
  return url.startsWith("https://");
}
