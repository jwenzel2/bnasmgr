const { defineConfig, devices } = require('@playwright/test');

const apiPort = 18080;
const webPort = 15173;
const apiOrigin = `http://127.0.0.1:${apiPort}`;

module.exports = defineConfig({
  testDir: './tests/e2e',
  timeout: 30_000,
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: `http://127.0.0.1:${webPort}`,
    trace: 'on-first-retry'
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] }
    }
  ],
  webServer: [
    {
      command: `node frontend/tests/e2e/prepare-db.mjs && env BNASMGR_DATABASE_URL=sqlite://target/e2e/playwright.db?mode=rwc BNASMGR_BIND=127.0.0.1:${apiPort} BNASMGR_SNAPSHOT_SCHEDULER=off BNASMGR_REPLICATION_SCHEDULER=off BNASMGR_ALERT_NOTIFIER=off cargo run -p bnasmgr-api`,
      url: `${apiOrigin}/api/health`,
      cwd: '..',
      timeout: 120_000,
      reuseExistingServer: false
    },
    {
      command: `env BNASMGR_API_ORIGIN=${apiOrigin} npm run dev -- --port ${webPort} --strictPort`,
      url: `http://127.0.0.1:${webPort}`,
      timeout: 60_000,
      reuseExistingServer: false
    }
  ]
});
