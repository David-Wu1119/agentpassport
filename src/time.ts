export function nowIso(): string {
  return new Date().toISOString();
}

export function addDuration(date: Date, duration: string): Date {
  const match = duration.match(/^(\d+)(m|h|d)$/);
  if (!match) {
    throw new Error(
      "Duration must use the form <number><m|h|d>, for example 30m, 2h, or 7d.",
    );
  }

  const amount = Number.parseInt(match[1] ?? "0", 10);
  const unit = match[2];
  const ms =
    unit === "m"
      ? amount * 60_000
      : unit === "h"
        ? amount * 3_600_000
        : amount * 86_400_000;
  return new Date(date.getTime() + ms);
}

export function isExpired(timestamp: string, now = new Date()): boolean {
  return new Date(timestamp).getTime() <= now.getTime();
}
