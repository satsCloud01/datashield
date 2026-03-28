import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests',
  timeout: 30000,
  use: {
    baseURL: 'http://localhost:5179',
    headless: true,
  },
  webServer: {
    command: 'npm run dev',
    port: 5179,
    reuseExistingServer: true,
  },
});
