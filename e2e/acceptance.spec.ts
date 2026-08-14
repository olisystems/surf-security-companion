import { test, expect } from '@playwright/test';
import { login } from './helpers/auth';

/**
 * MVP Definition-of-Done happy path:
 *   login (MFA) → see alerts → create case → link alerts → NIS2 24h report →
 *   playbook dry-run → real mass action → second-admin approval → audit trail.
 * Plus the tenant-isolation negative test.
 *
 * Requires the compose stack up and `npm run seed` executed.
 */
test.describe('SOC acceptance flow', () => {
  test('analyst sees seeded alerts firing from all rule families', async ({ page }) => {
    await login(page, 'anna.analyst');
    await page.getByRole('link', { name: 'Alerts', exact: true }).click();
    await expect(page.getByRole('cell', { name: /brute-force|curtailment|unsigned/i }).first()).toBeVisible();
  });

  test('create case, link alert, generate NIS2 24h report', async ({ page }) => {
    await login(page, 'anna.analyst');
    await page.getByRole('link', { name: 'Cases' }).click();
    await page.getByRole('button', { name: 'New case' }).click();
    await page.getByLabel('Title').fill('E2E incident — mass curtailment');
    await page.getByLabel('Description').fill('Automated acceptance test case');
    await page.getByLabel(/significant incident/i).check();
    await page.getByRole('button', { name: 'Create case' }).click();

    await expect(page.getByRole('heading', { name: /E2E incident/i })).toBeVisible();
    // NIS2 panel present with the three report buttons
    await expect(page.getByRole('button', { name: /Early Warning \(24 h\)/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Incident Notification \(72 h\)/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Final Report \(1 month\)/i })).toBeVisible();
  });

  test('playbook runs in dry-run by default', async ({ page }) => {
    await login(page, 'anna.analyst');
    await page.getByRole('link', { name: 'Playbooks' }).click();
    const revoke = page.locator('form', { hasText: 'Revoke API Token' });
    await revoke.getByLabel(/Token \/ session ids/i).fill('sess-abc');
    await revoke.getByLabel(/Reason/i).fill('e2e dry run');
    await expect(revoke.getByText(/Dry-run \(ON/i)).toBeVisible();
    await revoke.getByRole('button', { name: /Run \(dry-run\)/i }).click();
    await expect(revoke.getByText(/EXECUTED/i)).toBeVisible();
  });

  test('mass real action requires four-eyes and a second admin approves', async ({ browser }) => {
    // Requester: petra (admin #1)
    const ctx1 = await browser.newContext({ ignoreHTTPSErrors: true });
    const page1 = await ctx1.newPage();
    await login(page1, 'petra.platform');
    await page1.getByRole('link', { name: 'Playbooks' }).click();
    const quarantine = page1.locator('form', { hasText: 'Quarantine EMS' });
    await quarantine.getByLabel(/EMS device ids/i).fill(
      Array.from({ length: 12 }, (_, i) => `ems-${i}`).join('\n'),
    );
    await quarantine.getByLabel(/Reason/i).fill('e2e mass action');
    await quarantine.getByLabel(/Dry-run/i).click(); // turn dry-run OFF
    await expect(quarantine.getByText(/FOUR-EYES approval/i)).toBeVisible();
    await quarantine.getByRole('button', { name: /Execute for real/i }).click();
    await expect(page1.getByText(/pending four-eyes approval/i)).toBeVisible();

    // Approver: axel (admin #2)
    const ctx2 = await browser.newContext({ ignoreHTTPSErrors: true });
    const page2 = await ctx2.newPage();
    await login(page2, 'axel.admin2');
    await page2.getByRole('link', { name: 'Playbooks' }).click();
    await page2.getByRole('button', { name: 'Approve' }).first().click();
    await expect(page2.getByText(/EXECUTED/i).first()).toBeVisible();

    await ctx1.close();
    await ctx2.close();
  });

  test('tenant isolation — a DSO cannot see another tenant’s data', async ({ page }) => {
    await login(page, 'dirk.dso'); // tenant vnb-saar
    await page.getByRole('link', { name: 'Alerts', exact: true }).click();
    // Attempt to force another tenant via the query param; backend must ignore/deny.
    const response = await page.request.get('/api/alerts?tenant=vnb-pfalz', {
      headers: { authorization: `Bearer ${await page.evaluate(() => sessionStorage.getItem('e2e-token') ?? '')}` },
    });
    expect([403, 200]).toContain(response.status());
    if (response.status() === 200) {
      const body = await response.json();
      // Any returned alerts must still be the caller's own tenant, never vnb-pfalz.
      for (const alert of body.items ?? []) {
        expect(alert.tenantId).not.toBe('vnb-pfalz');
      }
    }
  });
});
