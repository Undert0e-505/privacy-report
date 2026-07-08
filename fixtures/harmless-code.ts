// This is a harmless TypeScript file that should not trigger any secret or PII scanners.
// It contains normal code with no secrets, keys, or personal information.

export function add(a: number, b: number): number {
  return a + b;
}

export function multiply(a: number, b: number): number {
  return a * b;
}

export function greet(name: string): string {
  return `Hello, ${name}!`;
}

const config = {
  port: 3000,
  host: 'localhost',
  retries: 3,
  timeout: 5000,
};

export default config;