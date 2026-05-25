import { expect, test } from '@playwright/test';

test('seeded admin can complete first login and browse dashboard sections', async ({ page }) => {
  await page.goto('/');

  await expect(page.getByRole('heading', { name: 'bnasmgr' })).toBeVisible();
  await page.getByLabel('Username').fill('admin');
  await page.getByLabel('Password').fill('admin');
  await page.getByRole('button', { name: 'Sign in' }).click();

  await expect(page.getByRole('heading', { name: 'Password required' })).toBeVisible();
  await page.getByLabel('Current password').fill('admin');
  await page.getByLabel('New password').fill('adminadmin');
  await page.getByRole('button', { name: 'Update password' }).click();

  await expect(page.locator('main > header h1')).toHaveText('storage');
  await expect(page.getByRole('button', { name: 'storage' })).toHaveClass(/active/);
  await expect(page.getByRole('heading', { name: 'Create dataset' })).toBeVisible();
  await expect(page.getByText('tank', { exact: true })).toBeVisible();
  const backupDatasetCard = page.locator('article.card').filter({ has: page.getByRole('heading', { name: 'tank/backups' }) });
  page.once('dialog', (dialog) => dialog.accept('wrong-dataset'));
  await backupDatasetCard.getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText('wrong-dataset')).toHaveCount(0);
  page.once('dialog', (dialog) => dialog.accept('tank/backups'));
  await backupDatasetCard.getByRole('button', { name: 'Delete' }).click();
  await expect(page.locator('main > header h1')).toHaveText('storage');

  await page.getByRole('button', { name: 'snapshots' }).click();
  await expect(page.locator('main > header h1')).toHaveText('snapshots');
  await expect(page.getByRole('heading', { name: 'Snapshot tasks' })).toBeVisible();
  await page.getByPlaceholder('file search in selected snapshot').fill('report');
  await page.getByRole('button', { name: 'Search files' }).click();
  await expect(page.getByText('docs/report.txt')).toBeVisible();
  await page.getByLabel('docs/report.txt').check();
  page.once('dialog', (dialog) => dialog.accept());
  await page.getByRole('button', { name: 'Restore selected' }).click();
  await expect(page.getByLabel('docs/report.txt')).not.toBeChecked();
  await page.getByPlaceholder('prefix').fill('e2e');
  await page.getByRole('button', { name: 'Save task' }).click();
  const snapshotTaskRow = page.getByRole('row').filter({ hasText: 'e2e' });
  await expect(snapshotTaskRow).toContainText('tank/media');
  await snapshotTaskRow.getByRole('button', { name: 'Run now' }).click();
  await expect(snapshotTaskRow).toContainText(/never run|\d{4}/);

  await page.getByRole('button', { name: 'shares' }).click();
  await expect(page.locator('main > header h1')).toHaveText('shares');
  await expect(page.getByRole('heading', { name: 'Samba', exact: true })).toBeVisible();
  const sambaShareForm = page.locator('form').filter({ has: page.getByRole('button', { name: 'Save Samba share' }) });
  await sambaShareForm.getByPlaceholder('share name').fill('e2e-share');
  await sambaShareForm.getByPlaceholder('/mnt/tank/share').fill('/mnt/tank/e2e-share');
  await sambaShareForm.getByPlaceholder('allowed users, comma separated').fill('admin');
  await sambaShareForm.getByRole('button', { name: 'Save Samba share' }).click();
  await expect(page.getByText('e2e-share /mnt/tank/e2e-share')).toBeVisible();

  const sambaUserForm = page.locator('form').filter({ has: page.getByRole('button', { name: 'Save Samba user' }) });
  await sambaUserForm.getByPlaceholder('storage username').fill('e2esmb');
  await sambaUserForm.getByPlaceholder('samba password').fill('password123');
  await sambaUserForm.getByRole('button', { name: 'Save Samba user' }).click();
  await expect(page.getByText('e2esmb enabled')).toBeVisible();

  const nfsForm = page.locator('form').filter({ has: page.getByRole('button', { name: 'Save NFS export' }) });
  await nfsForm.getByPlaceholder('/mnt/tank/share').fill('/mnt/tank/e2e-nfs');
  await nfsForm.getByPlaceholder('192.168.1.0/24').fill('127.0.0.1');
  await nfsForm.getByRole('button', { name: 'Save NFS export' }).click();
  await expect(page.getByText('/mnt/tank/e2e-nfs 127.0.0.1')).toBeVisible();

  const iscsiForm = page.locator('form').filter({ has: page.getByRole('button', { name: 'Save iSCSI target' }) });
  await iscsiForm.getByPlaceholder('target IQN').fill('iqn.2026-05.local.bnasmgr:e2e');
  await iscsiForm.getByPlaceholder('extent name').fill('e2edisk');
  await iscsiForm.getByPlaceholder('/dev/zvol/tank/iscsi/disk0').fill('/dev/zvol/tank/iscsi/e2edisk');
  await iscsiForm.getByRole('button', { name: 'Save iSCSI target' }).click();
  await expect(page.getByText('iqn.2026-05.local.bnasmgr:e2e LUN 0 /dev/zvol/tank/iscsi/e2edisk')).toBeVisible();

  await page.getByRole('button', { name: 'services' }).click();
  await expect(page.locator('main > header h1')).toHaveText('services');
  await expect(page.getByRole('heading', { name: 'System', exact: true })).toBeVisible();
  await expect(page.getByText('bnasmgr-mock')).toBeVisible();
  await expect(page.getByText('Mock CPU')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Network' })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'em0' })).toBeVisible();
  await expect(page.getByRole('cell', { name: '192.168.1.50' })).toBeVisible();
  const networkConfigForm = page.locator('form').filter({ has: page.getByRole('button', { name: 'Apply network config' }) });
  await networkConfigForm.getByPlaceholder('interface').fill('em0');
  await networkConfigForm.getByRole('combobox').selectOption('static');
  await networkConfigForm.getByPlaceholder('IPv4 address').fill('192.168.1.60');
  await networkConfigForm.getByPlaceholder('netmask').fill('255.255.255.0');
  await networkConfigForm.getByPlaceholder('default gateway, optional').fill('192.168.1.1');
  const saveNetworkResponse = page.waitForResponse((response) =>
    response.url().endsWith('/api/system/network/config') && response.request().method() === 'POST'
  );
  await networkConfigForm.getByRole('button', { name: 'Apply network config' }).click();
  await expect((await saveNetworkResponse).ok()).toBeTruthy();
  await expect(page.getByRole('cell', { name: '192.168.1.60' })).toBeVisible();
  const dnsConfigForm = page.locator('form').filter({ has: page.getByRole('button', { name: 'Apply DNS config' }) });
  await dnsConfigForm.getByPlaceholder('DNS nameservers').fill('1.1.1.1, 8.8.8.8');
  await dnsConfigForm.getByPlaceholder('search domains, optional').fill('lan, example.test');
  const saveDnsResponse = page.waitForResponse((response) =>
    response.url().endsWith('/api/system/network/dns') && response.request().method() === 'POST'
  );
  await dnsConfigForm.getByRole('button', { name: 'Apply DNS config' }).click();
  await expect((await saveDnsResponse).ok()).toBeTruthy();
  await expect(page.getByRole('cell', { name: '1.1.1.1, 8.8.8.8' })).toBeVisible();
  const staticRouteForm = page.locator('form').filter({ has: page.getByRole('button', { name: 'Apply static route' }) });
  await staticRouteForm.getByPlaceholder('route destination').fill('10.10.0.0/16');
  await staticRouteForm.getByPlaceholder('route gateway').fill('192.168.1.1');
  await staticRouteForm.getByPlaceholder('route description, optional').fill('lab route');
  const saveRouteResponse = page.waitForResponse((response) =>
    response.url().endsWith('/api/system/network/routes') && response.request().method() === 'POST'
  );
  await staticRouteForm.getByRole('button', { name: 'Apply static route' }).click();
  await expect((await saveRouteResponse).ok()).toBeTruthy();
  await expect(page.getByRole('cell', { name: '10.10.0.0/16' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'UPS' })).toBeVisible();
  await expect(page.getByText('Mock UPS 1500')).toBeVisible();
  const upsPolicyForm = page.locator('form').filter({ has: page.getByRole('button', { name: 'Save UPS policy' }) });
  await upsPolicyForm.getByLabel('Policy enabled').check();
  await upsPolicyForm.getByPlaceholder('low charge %').fill('25');
  await upsPolicyForm.getByPlaceholder('minimum runtime seconds').fill('600');
  await upsPolicyForm.getByRole('button', { name: 'Save UPS policy' }).click();
  page.once('dialog', (dialog) => dialog.accept('wrong-confirmation'));
  await page.getByRole('button', { name: 'Execute UPS shutdown' }).click();
  page.once('dialog', (dialog) => dialog.accept('EXECUTE UPS SHUTDOWN'));
  const executeUpsShutdownResponse = page.waitForResponse((response) =>
    response.url().endsWith('/api/system/ups/shutdown') && response.request().method() === 'POST'
  );
  await page.getByRole('button', { name: 'Execute UPS shutdown' }).click();
  await expect((await executeUpsShutdownResponse).ok()).toBeTruthy();
  const directoryForm = page.locator('form').filter({ has: page.getByRole('button', { name: 'Save directory service' }) });
  await directoryForm.getByLabel('Enabled').check();
  await directoryForm.getByPlaceholder('directory domain').fill('example.test');
  await directoryForm.getByPlaceholder('ldap://directory.example.test').fill('ldaps://directory.example.test');
  await directoryForm.getByPlaceholder('dc=example,dc=test').fill('dc=example,dc=test');
  await directoryForm.getByPlaceholder('bind DN, optional').fill('cn=readonly,dc=example,dc=test');
  const saveDirectoryResponse = page.waitForResponse((response) =>
    response.url().endsWith('/api/system/directory-service') && response.request().method() === 'POST'
  );
  await directoryForm.getByRole('button', { name: 'Save directory service' }).click();
  await expect((await saveDirectoryResponse).ok()).toBeTruthy();
  const sambaServiceCard = page.locator('article.card').filter({ has: page.getByRole('heading', { name: 'Samba', exact: true }) });
  await expect(sambaServiceCard).toContainText('running');
  await sambaServiceCard.getByRole('button', { name: 'Restart' }).click();
  await expect(sambaServiceCard).toContainText('running');

  await page.getByRole('button', { name: 'alerts' }).click();
  await expect(page.locator('main > header h1')).toHaveText('alerts');
  await expect(page.getByRole('heading', { name: 'Notifications' })).toBeVisible();
  const notificationsForm = page.locator('form').filter({ has: page.getByRole('button', { name: 'Save notifications' }) });
  await notificationsForm.getByLabel('Enabled').check();
  await notificationsForm.getByPlaceholder('webhook URL').fill('https://alerts.example.test/hook');
  const saveNotificationsResponse = page.waitForResponse((response) =>
    response.url().endsWith('/api/alerts/notifications') && response.request().method() === 'POST'
  );
  await notificationsForm.getByRole('button', { name: 'Save notifications' }).click();
  await expect((await saveNotificationsResponse).ok()).toBeTruthy();
  await expect(notificationsForm.getByRole('button', { name: 'Test' })).toBeEnabled();
  const testNotificationsResponse = page.waitForResponse((response) =>
    response.url().endsWith('/api/alerts/notifications/test') && response.request().method() === 'POST'
  );
  await notificationsForm.getByRole('button', { name: 'Test' }).click();
  await expect((await testNotificationsResponse).ok()).toBeTruthy();
  await expect(page.getByRole('cell', { name: 'webhook', exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'queued test for webhook transport' })).toBeVisible();
  await notificationsForm.getByPlaceholder('email recipient').fill('admin@example.test');
  await notificationsForm.getByPlaceholder('SMTP host').fill('127.0.0.1');
  await notificationsForm.getByRole('spinbutton').fill('1');
  await notificationsForm.getByPlaceholder('SMTP sender').fill('bnasmgr@example.test');
  const saveEmailNotificationsResponse = page.waitForResponse((response) =>
    response.url().endsWith('/api/alerts/notifications') && response.request().method() === 'POST'
  );
  await notificationsForm.getByRole('button', { name: 'Save notifications' }).click();
  await expect((await saveEmailNotificationsResponse).ok()).toBeTruthy();
  const testEmailNotificationsResponse = page.waitForResponse((response) =>
    response.url().endsWith('/api/alerts/notifications/test') && response.request().method() === 'POST'
  );
  await notificationsForm.getByRole('button', { name: 'Test' }).click();
  await expect((await testEmailNotificationsResponse).ok()).toBeTruthy();
  await expect(page.getByRole('cell', { name: 'email', exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: /email failed:/ }).first()).toBeVisible();

  await page.getByRole('button', { name: 'logs' }).click();
  await expect(page.locator('main > header h1')).toHaveText('logs');
  await page.getByPlaceholder('search').fill('e2e log entry');
  await expect(page.getByRole('button', { name: 'Filter' })).toBeVisible();
  await page.getByRole('button', { name: 'Filter' }).click();
  await expect(page.getByRole('cell', { name: 'e2e log entry' })).toBeVisible();

  await page.getByRole('button', { name: 'audit' }).click();
  await expect(page.locator('main > header h1')).toHaveText('audit');
  await expect(page.getByRole('heading', { name: 'Helper history' })).toBeVisible();

  await page.getByRole('button', { name: 'users' }).click();
  await expect(page.locator('main > header h1')).toHaveText('users');
  await expect(page.getByRole('heading', { name: 'Dashboard users' })).toBeVisible();
  await expect(page.getByRole('row').filter({ hasText: 'admin' }).filter({ hasText: 'active' })).toBeVisible();
  const createUserForm = page.locator('form').filter({ has: page.getByRole('button', { name: 'Create user' }) });
  await createUserForm.getByPlaceholder('username').fill('e2e-user');
  await createUserForm.getByPlaceholder('temporary password').fill('password123');
  await createUserForm.getByLabel('Admin').uncheck();
  await createUserForm.getByRole('button', { name: 'Create user' }).click();
  const userRow = page.getByRole('row').filter({ hasText: 'e2e-user' });
  await expect(userRow).toContainText('viewer');
  await expect(userRow).toContainText('password pending');
  page.once('dialog', (dialog) => dialog.accept('password456'));
  await userRow.getByRole('button', { name: 'Reset password' }).click();
  await expect(userRow).toContainText('password pending');

  await page.getByRole('button', { name: 'config' }).click();
  await expect(page.locator('main > header h1')).toHaveText('config');
  await expect(page.getByRole('heading', { name: 'Configuration' })).toBeVisible();
  await page.getByRole('button', { name: 'Export' }).click();
  const configBackup = page.getByPlaceholder('configuration backup JSON');
  await expect(configBackup).toHaveValue(/"shares_samba"/);
  await expect(configBackup).toHaveValue(/e2e-share/);
  await expect(configBackup).toHaveValue(/e2esmb/);
  await expect(configBackup).toHaveValue(/\/mnt\/tank\/e2e-nfs/);
  await expect(configBackup).toHaveValue(/iqn\.2026-05\.local\.bnasmgr:e2e/);
  await page.getByRole('button', { name: 'Import' }).click();
  await expect(configBackup).toHaveValue(/"version": 1/);
  await expect(configBackup).toHaveValue(/ups_policy/);
  await expect(configBackup).toHaveValue(/network_config/);
  await expect(configBackup).toHaveValue(/network_dns/);
  await expect(configBackup).toHaveValue(/network_routes/);
  await expect(configBackup).toHaveValue(/directory_service/);

  await page.getByRole('button', { name: 'shares' }).click();
  page.once('dialog', (dialog) => dialog.accept());
  await page.locator('li').filter({ hasText: 'e2e-share /mnt/tank/e2e-share' }).getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText('e2e-share /mnt/tank/e2e-share')).toHaveCount(0);
  page.once('dialog', (dialog) => dialog.accept());
  await page.locator('li').filter({ hasText: 'e2esmb enabled' }).getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText('e2esmb enabled')).toHaveCount(0);
  page.once('dialog', (dialog) => dialog.accept());
  await page.locator('li').filter({ hasText: '/mnt/tank/e2e-nfs 127.0.0.1' }).getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText('/mnt/tank/e2e-nfs 127.0.0.1')).toHaveCount(0);
  page.once('dialog', (dialog) => dialog.accept());
  await page.locator('li').filter({ hasText: 'iqn.2026-05.local.bnasmgr:e2e LUN 0 /dev/zvol/tank/iscsi/e2edisk' }).getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText('iqn.2026-05.local.bnasmgr:e2e LUN 0 /dev/zvol/tank/iscsi/e2edisk')).toHaveCount(0);

  await page.getByRole('button', { name: 'config' }).click();
  await page.getByLabel('Replace existing saved configuration').check();
  const replaceImportResponse = page.waitForResponse((response) =>
    response.url().endsWith('/api/config/import') && response.request().method() === 'POST'
  );
  page.once('dialog', (dialog) => dialog.accept());
  await page.getByRole('button', { name: 'Import' }).click();
  await expect((await replaceImportResponse).ok()).toBeTruthy();
  await page.getByRole('button', { name: 'shares' }).click();
  await expect(page.getByText('e2e-share /mnt/tank/e2e-share')).toBeVisible();
  await expect(page.getByText('e2esmb enabled')).toBeVisible();
  await expect(page.getByText('/mnt/tank/e2e-nfs 127.0.0.1')).toBeVisible();
  await expect(page.getByText('iqn.2026-05.local.bnasmgr:e2e LUN 0 /dev/zvol/tank/iscsi/e2edisk')).toBeVisible();

  await page.reload();
  await expect(page.locator('main > header h1')).toHaveText('storage');
  await page.getByRole('button', { name: 'audit' }).click();
  await expect(page.getByRole('cell', { name: 'mock dataset deleted' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: '1 file(s) restored from snapshot' }).first()).toBeVisible();
  await expect(page.getByText('snapshot task created')).toBeVisible();
  await expect(page.getByText('samba share saved')).toBeVisible();
  await expect(page.getByText('samba user saved')).toBeVisible();
  await expect(page.getByText('nfs export saved')).toBeVisible();
  await expect(page.getByText('iSCSI target saved')).toBeVisible();
  await expect(page.getByRole('cell', { name: 'alert notification settings saved' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'UPS shutdown command executed' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'network interface configuration saved' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'DNS resolver configuration saved' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'static route configuration saved' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'directory service settings saved' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'alert notification test queued for 1 channel(s)' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'configuration backup imported' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'samba share deleted' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'samba user deleted' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'nfs export deleted' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'iSCSI target deleted' }).first()).toBeVisible();
  await expect(page.getByText('dashboard user created')).toBeVisible();
  await expect(page.getByRole('cell', { name: 'Restart requested' }).first()).toBeVisible();
});
