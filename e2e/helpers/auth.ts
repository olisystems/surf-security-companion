import { type Page, expect } from '@playwright/test';

/**
 * Drives the Keycloak login form (password + OTP) for a demo user. WebAuthn
 * can't be scripted in headless Chromium, so the demo users are configured
 * with OTP; the e2e OTP secret is injected via KC for the test realm.
 */
export async function login(page: Page, username: string, password = 'Surf-Demo-2026!'): Promise<void> {
  await page.goto('/');
  await page.getByRole('button', { name: /sign in with keycloak/i }).click();

  await page.waitForURL(/\/realms\/surf-security\/protocol\/openid-connect\/auth/);
  await page.getByLabel(/username|email/i).fill(username);
  // getByRole('textbox') instead of getByLabel: Keycloak 26 login themes with a
  // show-password toggle expose a second element whose aria-label also matches
  // /password/i, which trips Playwright's strict mode.
  await page.getByRole('textbox', { name: /password/i }).fill(password);
  await page.getByRole('button', { name: /sign in|log in/i }).click();

  // OTP step (if the account has completed enrolment in the seeded realm)
  const otpField = page.getByLabel(/one-time code|otp/i);
  if (await otpField.isVisible({ timeout: 3000 }).catch(() => false)) {
    const { authenticator } = await import('otplib');
    const secret = process.env[`E2E_OTP_${username.replace(/\W/g, '_').toUpperCase()}`];
    if (secret) await otpField.fill(authenticator.generate(secret));
    await page.getByRole('button', { name: /sign in|log in|submit/i }).click();
  }

  await expect(page.getByRole('heading', { name: /SURF Security Companion/i })).toBeVisible();
}
