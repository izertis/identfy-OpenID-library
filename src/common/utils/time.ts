/**
 * Express a date in second
 * @param ms Date to express in seconds
 * @returns Seconds from the EPOCH
 */
export function expressDateInSeconds(date: string) {
  return Math.floor(Date.parse(date) / 1000);
}
