const JITTER_MAX_MS = 50;

export function addJitter(): Promise<void> {
  return new Promise((resolve) =>
    setTimeout(resolve, Math.floor(Math.random() * JITTER_MAX_MS))
  );
}
