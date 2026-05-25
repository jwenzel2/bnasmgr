<script>
  const apiBase = '';
  let token = localStorage.getItem('bnasmgr_token') || '';
  let user = null;
  let error = '';
  let active = 'storage';
  let loginForm = { username: 'admin', password: 'admin' };
  let passwordForm = { current_password: 'admin', new_password: '' };
  let storage = { pools: [], datasets: [] };
  let scrubStatus = {};
  let disks = [];
  let smartTestHistory = {};
  let snapshots = [];
  let snapshotTasks = [];
  let replicationTasks = [];
  let services = [];
  let systemReport = null;
  let networkInterfaces = [];
  let networkConfigs = [];
  let dnsConfig = { nameservers: [], search_domains: [] };
  let staticRoutes = [];
  let upsStatus = null;
  let upsPolicy = { enabled: false, low_charge_percent: 20, min_runtime_seconds: 300, shutdown_command: 'shutdown -p now' };
  let directoryService = { enabled: false, provider: 'ldap', domain: '', uri: '', base_dn: '', bind_dn: '', tls: true };
  let sambaShares = [];
  let sambaSettings = { workgroup: 'WORKGROUP', server_string: 'bnasmgr NAS', netbios_name: 'BNASMGR', security: 'user', map_to_guest: 'Bad User', log_level: '1' };
  let sambaUsers = [];
  let nfsShares = [];
  let iscsiTargets = [];
  let alerts = [];
  let alertNotifications = { enabled: false, min_severity: 'warning', webhook_url: '', email_to: '', smtp_host: '', smtp_port: 25, smtp_from: '', smtp_tls: 'none', smtp_username: '', smtp_password: '' };
  let alertNotificationHistory = [];
  let logs = [];
  let audit = [];
  let helperHistory = [];
  let users = [];
  let localUsers = [];
  let localGroups = [];
  let datasetForm = { name: 'tank/newdata', compression: 'lz4', atime: 'off', quota: 'none', reservation: 'none', mountpoint: '' };
  let snapshotForm = { dataset: 'tank/media', name: '' };
  let snapshotTaskForm = { dataset: 'tank/media', prefix: 'auto', cadence: 'daily', retention_count: 14, enabled: true };
  let replicationTaskForm = { source_dataset: 'tank/media', destination_dataset: 'backup/media', mode: 'local', remote_host: '', remote_user: '', cadence: 'daily', retention_count: 14, enabled: true };
  let snapshotFileSnapshot = '';
  let snapshotFileSearch = '';
  let snapshotFiles = [];
  let selectedSnapshotFiles = {};
  let snapshotCloneForm = { snapshot: '', target_dataset: 'tank/clone' };
  let snapshotDiffForm = { snapshot: '', to_snapshot: '' };
  let snapshotDiff = [];
  let sambaForm = { name: '', path: '', allowed_users: '', readonly: false };
  let sambaUserForm = { username: '', password: '', enabled: true };
  let nfsForm = { path: '', clients: '', options: '-maproot=root' };
  let iscsiForm = { name: 'iqn.2026-05.local.bnasmgr:disk0', portal_group: 'pg0', initiator_name: '', auth_group: 'no-authentication', extent_name: 'disk0', path: '/dev/zvol/tank/iscsi/disk0', size: '', lun_id: 0, readonly: false };
  let userForm = { username: '', password: '', is_admin: true };
  let localUserForm = { username: '', full_name: '', shell: '/bin/sh', home: '', groups: '', password: '', create_home: true };
  let localGroupForm = { name: '', members: '' };
  let logFilters = { service: '', severity: '', search: '', from: '', to: '' };
  let networkConfigForm = { name: 'em0', mode: 'dhcp', ipv4_address: '', netmask: '255.255.255.0', gateway: '' };
  let dnsConfigForm = { nameservers: '1.1.1.1, 8.8.8.8', search_domains: 'lan' };
  let staticRouteForm = { destination: '10.0.0.0/24', gateway: '192.168.1.1', description: '' };
  let configBackupText = '';
  let configImportReplace = false;

  async function request(path, init = {}) {
    error = '';
    const headers = { 'content-type': 'application/json', ...(init.headers || {}) };
    if (token) headers.authorization = `Bearer ${token}`;
    const response = await fetch(`${apiBase}${path}`, { ...init, headers });
    const text = await response.text();
    const data = text ? JSON.parse(text) : null;
    if (!response.ok) {
      error = data?.error || response.statusText;
      throw new Error(error);
    }
    return data;
  }

  async function login() {
    const data = await request('/api/auth/login', { method: 'POST', body: JSON.stringify(loginForm) });
    token = data.token;
    user = data.user;
    localStorage.setItem('bnasmgr_token', token);
    if (!user.must_change_password) await loadAll();
  }

  async function changePassword() {
    user = await request('/api/auth/change-password', { method: 'POST', body: JSON.stringify(passwordForm) });
    passwordForm = { current_password: '', new_password: '' };
    await loadAll();
  }

  async function loadAll() {
    if (!token || user?.must_change_password) return;
    await Promise.all([loadStorage(), loadDiskHealth(), loadSnapshots(), loadSnapshotTasks(), loadReplicationTasks(), loadServices(), loadSystemReport(), loadNetworkInterfaces(), loadNetworkConfigs(), loadDnsConfig(), loadStaticRoutes(), loadUpsStatus(), loadUpsPolicy(), loadDirectoryService(), loadShares(), loadAlerts(), loadAlertNotifications(), loadAlertNotificationHistory(), loadLogs(), loadAudit(), loadHelperHistory(), loadUsers()]);
  }

  async function restoreSession() {
    if (!token) return;
    try {
      user = await request('/api/auth/me');
      await loadAll();
    } catch {
      token = '';
      localStorage.removeItem('bnasmgr_token');
    }
  }

  async function loadStorage() {
    storage = await request('/api/storage/overview');
    await loadScrubStatuses();
  }

  async function loadScrubStatuses() {
    const entries = await Promise.all(storage.pools.map(async (pool) => [pool.name, await request(`/api/storage/pools/${encodeURIComponent(pool.name)}/scrub`)]));
    scrubStatus = Object.fromEntries(entries);
  }

  async function loadDiskHealth() {
    try {
      disks = await request('/api/storage/disks');
    } catch {
      disks = [];
    }
  }

  async function scrubAction(pool, action) {
    await request(`/api/storage/pools/${encodeURIComponent(pool)}/scrub/${action}`, { method: 'POST' });
    await loadScrubStatuses();
  }

  async function loadSmartTests(disk) {
    const params = new URLSearchParams({ device: disk.name });
    if (disk.device_type && disk.device_type !== 'auto') params.set('device_type', disk.device_type);
    smartTestHistory = { ...smartTestHistory, [disk.name]: await request(`/api/storage/disks/tests?${params}`) };
  }

  async function startSmartTest(disk, test) {
    await request('/api/storage/disks/tests', {
      method: 'POST',
      body: JSON.stringify({
        device: disk.name,
        device_type: disk.device_type === 'auto' ? null : disk.device_type,
        test
      })
    });
    await loadSmartTests(disk);
  }

  async function setQuota(dataset, event) {
    const form = new FormData(event.currentTarget);
    const quota = String(form.get('quota') || '').trim();
    if (!quota) return;
    await request('/api/storage/quota', {
      method: 'POST',
      body: JSON.stringify({ dataset, quota })
    });
    await loadStorage();
  }

  function datasetPropertiesFromForm(form, name) {
    return {
      name,
      compression: String(form.get('compression') || '').trim(),
      atime: String(form.get('atime') || '').trim(),
      quota: String(form.get('quota') || '').trim(),
      reservation: String(form.get('reservation') || '').trim(),
      mountpoint: String(form.get('mountpoint') || '').trim()
    };
  }

  async function createDataset() {
    await request('/api/storage/datasets', {
      method: 'POST',
      body: JSON.stringify(datasetForm)
    });
    await loadStorage();
  }

  async function updateDatasetProperties(dataset, event) {
    const form = new FormData(event.currentTarget);
    await request('/api/storage/datasets/properties', {
      method: 'POST',
      body: JSON.stringify(datasetPropertiesFromForm(form, dataset))
    });
    await loadStorage();
  }

  async function deleteDataset(dataset) {
    const confirmed = prompt(`Type ${dataset} to delete this dataset`);
    if (confirmed !== dataset) return;
    await request('/api/storage/datasets/delete', {
      method: 'POST',
      headers: { 'x-bnasmgr-confirm': dataset },
      body: JSON.stringify({ name: dataset })
    });
    await loadStorage();
  }

  async function loadSnapshots() {
    snapshots = await request(`/api/snapshots?dataset=${encodeURIComponent(snapshotForm.dataset)}`);
    snapshotFileSnapshot = snapshots[0]?.name || '';
    snapshotCloneForm = { ...snapshotCloneForm, snapshot: snapshots[0]?.name || '' };
    snapshotDiffForm = { ...snapshotDiffForm, snapshot: snapshots[0]?.name || '' };
    snapshotFiles = [];
    selectedSnapshotFiles = {};
    snapshotDiff = [];
  }

  async function createSnapshot() {
    await request('/api/snapshots', { method: 'POST', body: JSON.stringify(snapshotForm) });
    snapshotForm.name = '';
    await loadSnapshots();
  }

  async function loadSnapshotTasks() {
    snapshotTasks = await request('/api/snapshots/tasks');
  }

  async function createSnapshotTask() {
    await request('/api/snapshots/tasks', {
      method: 'POST',
      body: JSON.stringify({
        ...snapshotTaskForm,
        retention_count: Number(snapshotTaskForm.retention_count)
      })
    });
    snapshotTaskForm = { ...snapshotTaskForm, prefix: 'auto' };
    await loadSnapshotTasks();
  }

  async function deleteSnapshotTask(id, prefix) {
    if (!confirm(`Delete snapshot task ${prefix}?`)) return;
    await request(`/api/snapshots/tasks/${encodeURIComponent(id)}`, { method: 'DELETE' });
    await loadSnapshotTasks();
  }

  async function runSnapshotTask(id) {
    await request(`/api/snapshots/tasks/${encodeURIComponent(id)}/run`, { method: 'POST' });
    await Promise.all([loadSnapshots(), loadSnapshotTasks()]);
  }

  async function loadReplicationTasks() {
    replicationTasks = await request('/api/replication/tasks');
  }

  async function createReplicationTask() {
    await request('/api/replication/tasks', {
      method: 'POST',
      body: JSON.stringify({
        ...replicationTaskForm,
        retention_count: Number(replicationTaskForm.retention_count)
      })
    });
    replicationTaskForm = { ...replicationTaskForm, remote_host: '', remote_user: '' };
    await loadReplicationTasks();
  }

  async function deleteReplicationTask(id, source) {
    if (!confirm(`Delete replication task for ${source}?`)) return;
    await request(`/api/replication/tasks/${encodeURIComponent(id)}`, { method: 'DELETE' });
    await loadReplicationTasks();
  }

  async function runReplicationTask(id) {
    await request(`/api/replication/tasks/${encodeURIComponent(id)}/run`, { method: 'POST' });
    await loadReplicationTasks();
  }

  async function deleteSnapshot(name) {
    if (!confirm(`Delete snapshot ${name}?`)) return;
    await request(`/api/snapshots/${encodeURIComponent(name)}`, {
      method: 'DELETE',
      headers: { 'x-bnasmgr-confirm': name }
    });
    await loadSnapshots();
  }

  async function rollbackSnapshot(name) {
    if (!confirm(`Rollback ${name}? Newer data may be lost.`)) return;
    await request(`/api/snapshots/${encodeURIComponent(name)}/rollback`, {
      method: 'POST',
      headers: { 'x-bnasmgr-confirm': name }
    });
  }

  async function cloneSnapshot() {
    if (!snapshotCloneForm.snapshot || !snapshotCloneForm.target_dataset.trim()) return;
    await request(`/api/snapshots/${encodeURIComponent(snapshotCloneForm.snapshot)}/clone`, {
      method: 'POST',
      body: JSON.stringify({ target_dataset: snapshotCloneForm.target_dataset.trim() })
    });
    await loadStorage();
  }

  async function loadSnapshotDiff() {
    if (!snapshotDiffForm.snapshot) return;
    const params = new URLSearchParams();
    if (snapshotDiffForm.to_snapshot.trim()) params.set('to_snapshot', snapshotDiffForm.to_snapshot.trim());
    snapshotDiff = await request(`/api/snapshots/${encodeURIComponent(snapshotDiffForm.snapshot)}/diff?${params}`);
  }

  async function searchSnapshotFiles(name) {
    const params = new URLSearchParams();
    if (snapshotFileSearch.trim()) params.set('search', snapshotFileSearch.trim());
    snapshotFiles = await request(`/api/snapshots/${encodeURIComponent(name)}/files?${params}`);
    selectedSnapshotFiles = {};
  }

  function toggleSnapshotFile(path) {
    selectedSnapshotFiles = { ...selectedSnapshotFiles, [path]: !selectedSnapshotFiles[path] };
  }

  async function restoreSnapshotFiles(name) {
    const files = Object.entries(selectedSnapshotFiles).filter(([, selected]) => selected).map(([path]) => path);
    if (!files.length) return;
    if (!confirm(`Restore ${files.length} file(s) from ${name}? Existing files will be overwritten.`)) return;
    await request(`/api/snapshots/${encodeURIComponent(name)}/files/restore`, {
      method: 'POST',
      headers: { 'x-bnasmgr-confirm': name },
      body: JSON.stringify({ files })
    });
    selectedSnapshotFiles = {};
  }

  async function loadServices() {
    services = await request('/api/services');
  }

  async function loadSystemReport() {
    try {
      systemReport = await request('/api/system/report');
    } catch {
      systemReport = null;
    }
  }

  async function loadNetworkInterfaces() {
    try {
      networkInterfaces = await request('/api/system/network');
    } catch {
      networkInterfaces = [];
    }
  }

  async function loadNetworkConfigs() {
    networkConfigs = await request('/api/system/network/config');
  }

  async function saveNetworkConfig() {
    networkConfigs = await request('/api/system/network/config', {
      method: 'POST',
      body: JSON.stringify({
        ...networkConfigForm,
        ipv4_address: networkConfigForm.mode === 'static' ? networkConfigForm.ipv4_address : '',
        netmask: networkConfigForm.mode === 'static' ? networkConfigForm.netmask : '',
        gateway: networkConfigForm.gateway
      })
    });
    await Promise.all([loadNetworkInterfaces(), loadAudit(), loadHelperHistory()]);
  }

  async function loadDnsConfig() {
    dnsConfig = await request('/api/system/network/dns');
    dnsConfigForm = {
      nameservers: Array.isArray(dnsConfig.nameservers) ? dnsConfig.nameservers.join(', ') : '',
      search_domains: Array.isArray(dnsConfig.search_domains) ? dnsConfig.search_domains.join(', ') : ''
    };
  }

  async function saveDnsConfig() {
    dnsConfig = await request('/api/system/network/dns', {
      method: 'POST',
      body: JSON.stringify({
        nameservers: dnsConfigForm.nameservers.split(',').map((item) => item.trim()).filter(Boolean),
        search_domains: dnsConfigForm.search_domains.split(',').map((item) => item.trim()).filter(Boolean)
      })
    });
    await Promise.all([loadAudit(), loadHelperHistory()]);
  }

  async function loadStaticRoutes() {
    staticRoutes = await request('/api/system/network/routes');
  }

  async function saveStaticRoute() {
    staticRoutes = await request('/api/system/network/routes', {
      method: 'POST',
      body: JSON.stringify(staticRouteForm)
    });
    await Promise.all([loadAudit(), loadHelperHistory()]);
  }

  async function loadUpsStatus() {
    try {
      upsStatus = await request('/api/system/ups');
    } catch {
      upsStatus = null;
    }
  }

  async function loadUpsPolicy() {
    upsPolicy = await request('/api/system/ups/policy');
  }

  async function saveUpsPolicy() {
    upsPolicy = await request('/api/system/ups/policy', {
      method: 'POST',
      body: JSON.stringify({
        ...upsPolicy,
        low_charge_percent: Number(upsPolicy.low_charge_percent),
        min_runtime_seconds: Number(upsPolicy.min_runtime_seconds)
      })
    });
    await loadAlerts();
  }

  async function executeUpsShutdown() {
    const confirmed = prompt('Type EXECUTE UPS SHUTDOWN to run the configured shutdown command');
    if (confirmed !== 'EXECUTE UPS SHUTDOWN') return;
    await request('/api/system/ups/shutdown', {
      method: 'POST',
      headers: { 'x-bnasmgr-confirm': 'EXECUTE UPS SHUTDOWN' },
      body: JSON.stringify({})
    });
    await loadAudit();
    await loadHelperHistory();
  }

  async function loadDirectoryService() {
    directoryService = await request('/api/system/directory-service');
  }

  async function saveDirectoryService() {
    directoryService = await request('/api/system/directory-service', {
      method: 'POST',
      body: JSON.stringify(directoryService)
    });
  }

  async function serviceAction(service, action) {
    await request(`/api/services/${service}/${action}`, { method: 'POST' });
    await loadServices();
  }

  async function loadShares() {
    [sambaShares, sambaSettings, sambaUsers, nfsShares, iscsiTargets] = await Promise.all([request('/api/shares/samba'), request('/api/shares/samba/settings'), request('/api/shares/samba/users'), request('/api/shares/nfs'), request('/api/shares/iscsi')]);
  }

  async function saveSambaSettings() {
    sambaSettings = await request('/api/shares/samba/settings', {
      method: 'POST',
      body: JSON.stringify(sambaSettings)
    });
    await loadShares();
  }

  async function saveSamba() {
    await request('/api/shares/samba', {
      method: 'POST',
      body: JSON.stringify({ ...sambaForm, allowed_users: sambaForm.allowed_users.split(',').map((u) => u.trim()).filter(Boolean) })
    });
    sambaForm = { name: '', path: '', allowed_users: '', readonly: false };
    await loadShares();
  }

  async function deleteSamba(id, name) {
    if (!confirm(`Delete Samba share ${name}?`)) return;
    await request(`/api/shares/samba/${encodeURIComponent(id)}`, { method: 'DELETE' });
    await loadShares();
  }

  async function saveSambaUser() {
    await request('/api/shares/samba/users', {
      method: 'POST',
      body: JSON.stringify(sambaUserForm)
    });
    sambaUserForm = { username: '', password: '', enabled: true };
    await loadShares();
  }

  async function deleteSambaUser(username) {
    if (!confirm(`Delete Samba user ${username}?`)) return;
    await request(`/api/shares/samba/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
    await loadShares();
  }

  async function saveNfs() {
    await request('/api/shares/nfs', { method: 'POST', body: JSON.stringify(nfsForm) });
    nfsForm = { path: '', clients: '', options: '-maproot=root' };
    await loadShares();
  }

  async function deleteNfs(id, path) {
    if (!confirm(`Delete NFS export ${path}?`)) return;
    await request(`/api/shares/nfs/${encodeURIComponent(id)}`, { method: 'DELETE' });
    await loadShares();
  }

  async function saveIscsi() {
    await request('/api/shares/iscsi', {
      method: 'POST',
      body: JSON.stringify({ ...iscsiForm, lun_id: Number(iscsiForm.lun_id) })
    });
    iscsiForm = { ...iscsiForm, name: '', extent_name: '', path: '', size: '', lun_id: 0, readonly: false };
    await loadShares();
  }

  async function deleteIscsi(id, name) {
    if (!confirm(`Delete iSCSI target ${name}?`)) return;
    await request(`/api/shares/iscsi/${encodeURIComponent(id)}`, { method: 'DELETE' });
    await loadShares();
  }

  async function loadLogs() {
    const params = new URLSearchParams(Object.entries(logFilters).filter(([, v]) => v).map(([key, value]) => {
      if ((key === 'from' || key === 'to') && value) return [key, new Date(value).toISOString()];
      return [key, value];
    }));
    logs = await request(`/api/logs?${params}`);
  }

  async function loadAlerts() {
    alerts = await request('/api/alerts');
  }

  async function loadAlertNotifications() {
    alertNotifications = await request('/api/alerts/notifications');
  }

  async function loadAlertNotificationHistory() {
    alertNotificationHistory = await request('/api/alerts/notifications/history');
  }

  async function saveAlertNotifications() {
    alertNotifications = await request('/api/alerts/notifications', {
      method: 'POST',
      body: JSON.stringify(alertNotifications)
    });
  }

  async function testAlertNotifications() {
    await request('/api/alerts/notifications/test', { method: 'POST' });
    await Promise.all([loadAlertNotificationHistory(), loadAudit()]);
  }

  async function loadAudit() {
    audit = await request('/api/audit');
  }

  async function loadHelperHistory() {
    helperHistory = await request('/api/audit/helper-history');
  }

  async function loadUsers() {
    [users, localUsers, localGroups] = await Promise.all([request('/api/users'), request('/api/system/users'), request('/api/system/groups')]);
  }

  async function createUser() {
    await request('/api/users', { method: 'POST', body: JSON.stringify(userForm) });
    userForm = { username: '', password: '', is_admin: true };
    await loadUsers();
  }

  async function setUserRole(id, isAdmin) {
    await request(`/api/users/${encodeURIComponent(id)}/role`, {
      method: 'POST',
      body: JSON.stringify({ is_admin: isAdmin })
    });
    await loadUsers();
  }

  async function resetUserPassword(id, username) {
    const password = prompt(`Temporary password for ${username}`);
    if (!password) return;
    await request(`/api/users/${encodeURIComponent(id)}/reset-password`, {
      method: 'POST',
      body: JSON.stringify({ password })
    });
    await loadUsers();
  }

  async function deleteUser(id, username) {
    if (!confirm(`Delete dashboard user ${username}?`)) return;
    await request(`/api/users/${encodeURIComponent(id)}`, { method: 'DELETE' });
    await loadUsers();
  }

  async function saveLocalUser() {
    await request('/api/system/users', {
      method: 'POST',
      body: JSON.stringify({
        ...localUserForm,
        groups: localUserForm.groups.split(',').map((item) => item.trim()).filter(Boolean),
        password: localUserForm.password || null
      })
    });
    localUserForm = { ...localUserForm, username: '', full_name: '', home: '', groups: '', password: '' };
    await loadUsers();
  }

  async function deleteLocalUser(username) {
    if (!confirm(`Delete local user ${username}?`)) return;
    await request(`/api/system/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
    await loadUsers();
  }

  async function saveLocalGroup() {
    await request('/api/system/groups', {
      method: 'POST',
      body: JSON.stringify({
        name: localGroupForm.name,
        members: localGroupForm.members.split(',').map((item) => item.trim()).filter(Boolean)
      })
    });
    localGroupForm = { name: '', members: '' };
    await loadUsers();
  }

  async function deleteLocalGroup(name) {
    if (!confirm(`Delete local group ${name}?`)) return;
    await request(`/api/system/groups/${encodeURIComponent(name)}`, { method: 'DELETE' });
    await loadUsers();
  }

  async function exportConfig() {
    const backup = await request('/api/config/export');
    configBackupText = JSON.stringify(backup, null, 2);
  }

  async function importConfig() {
    if (!configBackupText.trim()) return;
    const backup = JSON.parse(configBackupText);
    if (configImportReplace && !confirm('Replace existing saved configuration?')) return;
    await request('/api/config/import', {
      method: 'POST',
      body: JSON.stringify({ backup, replace: configImportReplace })
    });
    await loadAll();
  }

  function logout() {
    token = '';
    user = null;
    localStorage.removeItem('bnasmgr_token');
  }

  function sizeToBytes(value) {
    if (value === null || value === undefined) return 0;
    const match = String(value).trim().match(/^([\d.]+)\s*([KMGTPE]?)(?:i?B?)?$/i);
    if (!match) return 0;
    const number = Number.parseFloat(match[1]);
    if (!Number.isFinite(number)) return 0;
    const unit = match[2].toUpperCase();
    const power = ['', 'K', 'M', 'G', 'T', 'P', 'E'].indexOf(unit);
    return number * Math.pow(1024, Math.max(power, 0));
  }

  function usage(item) {
    const used = sizeToBytes(item.used);
    const free = sizeToBytes(item.available);
    const total = used + free;
    const percent = total > 0 ? Math.round((used / total) * 100) : 0;
    return {
      percent: Math.min(100, Math.max(0, percent)),
      used: item.used || '0',
      free: item.available || '0'
    };
  }

  function runtimeLabel(seconds) {
    const value = Number(seconds);
    if (!Number.isFinite(value) || value <= 0) return 'unknown';
    const minutes = Math.round(value / 60);
    if (minutes < 60) return `${minutes} min`;
    const hours = Math.floor(minutes / 60);
    const remainder = minutes % 60;
    return `${hours}h ${remainder}m`;
  }

  function bytesLabel(bytes) {
    const value = Number(bytes);
    if (!Number.isFinite(value) || value <= 0) return 'unknown';
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let current = value;
    let index = 0;
    while (current >= 1024 && index < units.length - 1) {
      current /= 1024;
      index += 1;
    }
    return `${current.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
  }

  restoreSession();
</script>

{#if !user}
  <main class="login">
    <form class="panel auth" on:submit|preventDefault={login}>
      <h1>bnasmgr</h1>
      <label>Username <input bind:value={loginForm.username} autocomplete="username" /></label>
      <label>Password <input bind:value={loginForm.password} type="password" autocomplete="current-password" /></label>
      <button>Sign in</button>
      {#if error}<p class="error">{error}</p>{/if}
    </form>
  </main>
{:else if user.must_change_password}
  <main class="login">
    <form class="panel auth" on:submit|preventDefault={changePassword}>
      <h1>Password required</h1>
      <label>Current password <input bind:value={passwordForm.current_password} type="password" /></label>
      <label>New password <input bind:value={passwordForm.new_password} type="password" /></label>
      <button>Update password</button>
      {#if error}<p class="error">{error}</p>{/if}
    </form>
  </main>
{:else}
  <div class="shell">
    <aside>
      <div class="brand">bnasmgr</div>
      {#each ['storage', 'snapshots', 'shares', 'services', 'alerts', 'logs', 'audit', 'users', 'config'] as tab}
        <button class:active={active === tab} on:click={() => active = tab}>{tab}</button>
      {/each}
      <button on:click={logout}>logout</button>
    </aside>
    <main>
      <header>
        <h1>{active}</h1>
        <span>{user.username}</span>
      </header>
      {#if error}<p class="error">{error}</p>{/if}

      {#if active === 'storage'}
        <section class="grid storage-grid">
          <article class="card">
            <h2>Create dataset</h2>
            <form class="stack" on:submit|preventDefault={createDataset}>
              <input bind:value={datasetForm.name} placeholder="dataset name" />
              <select bind:value={datasetForm.compression}>
                <option value="">compression: inherit</option>
                <option value="lz4">compression: lz4</option>
                <option value="zstd">compression: zstd</option>
                <option value="on">compression: on</option>
                <option value="off">compression: off</option>
              </select>
              <select bind:value={datasetForm.atime}>
                <option value="">atime: inherit</option>
                <option value="off">atime: off</option>
                <option value="on">atime: on</option>
              </select>
              <input bind:value={datasetForm.quota} placeholder="quota, e.g. 2T or none" />
              <input bind:value={datasetForm.reservation} placeholder="reservation, e.g. 500G or none" />
              <input bind:value={datasetForm.mountpoint} placeholder="mountpoint, blank for default" />
              <button>Create dataset</button>
            </form>
          </article>
          {#each storage.pools as pool}
            <article class="card pool-card">
              <div>
                <h2>{pool.name}</h2>
                <span class:green={pool.health === 'online'} class="status">{pool.health}</span>
              </div>
              <div class="usage-chart" style={`--used:${usage(pool).percent}%`} aria-label={`${pool.name} ${usage(pool).percent}% used`}>
                <span>{usage(pool).percent}%</span>
              </div>
              <div class="usage-legend">
                <span><i class="used"></i>Used {usage(pool).used}</span>
                <span><i class="free"></i>Free {usage(pool).free}</span>
              </div>
              <div class="scrub-status">
                <span class="status {scrubStatus[pool.name]?.state === 'running' ? 'yellow' : 'green'}">{scrubStatus[pool.name]?.state || 'unknown'}</span>
                <p>{scrubStatus[pool.name]?.message || 'scrub status unavailable'}</p>
                <div class="actions">
                  <button on:click={() => scrubAction(pool.name, 'start')}>Start scrub</button>
                  <button on:click={() => scrubAction(pool.name, 'stop')}>Stop scrub</button>
                </div>
              </div>
            </article>
          {/each}
          {#each storage.datasets as ds}
            <article class="card">
              <div class="card-heading">
                <h2>{ds.name}</h2>
                <div class="usage-chart small" style={`--used:${usage(ds).percent}%`} aria-label={`${ds.name} ${usage(ds).percent}% used`}>
                  <span>{usage(ds).percent}%</span>
                </div>
              </div>
              <div class="usage-legend compact">
                <span><i class="used"></i>Used {usage(ds).used}</span>
                <span><i class="free"></i>Free {usage(ds).free}</span>
              </div>
              <dl><dt>Used</dt><dd>{ds.used}</dd><dt>Available</dt><dd>{ds.available}</dd><dt>Quota</dt><dd>{ds.quota || 'none'}</dd><dt>Reserved</dt><dd>{ds.reservation || 'none'}</dd><dt>Mount</dt><dd>{ds.mountpoint}</dd><dt>Compression</dt><dd>{ds.compression || 'inherit'}</dd><dt>Atime</dt><dd>{ds.atime || 'inherit'}</dd><dt>Snapshots</dt><dd>{ds.snapshots}</dd></dl>
              <form class="quota-form" on:submit|preventDefault={(event) => setQuota(ds.name, event)}>
                <input name="quota" value={ds.quota || ''} placeholder="quota, e.g. 2T or none" />
                <button>Set quota</button>
              </form>
              <form class="stack" on:submit|preventDefault={(event) => updateDatasetProperties(ds.name, event)}>
                <select name="compression">
                  <option value="">compression: unchanged</option>
                  <option value="lz4">compression: lz4</option>
                  <option value="zstd">compression: zstd</option>
                  <option value="on">compression: on</option>
                  <option value="off">compression: off</option>
                </select>
                <select name="atime">
                  <option value="">atime: unchanged</option>
                  <option value="off">atime: off</option>
                  <option value="on">atime: on</option>
                </select>
                <input name="quota" value={ds.quota || ''} placeholder="quota" />
                <input name="reservation" value={ds.reservation || ''} placeholder="reservation" />
                <input name="mountpoint" value={ds.mountpoint || ''} placeholder="mountpoint" />
                <div class="actions">
                  <button>Save properties</button>
                  <button type="button" on:click={() => deleteDataset(ds.name)}>Delete</button>
                </div>
              </form>
              <span class:green={ds.health === 'online'} class="status">{ds.health}</span>
            </article>
          {/each}
        </section>
        {#if disks.length}
          <section class="panel disk-panel">
            <h2>Disk health</h2>
            <table>
              <tbody>
                {#each disks as disk}
                  <tr>
                    <td>{disk.name}</td>
                    <td>{disk.model}</td>
                    <td>{disk.serial}</td>
                    <td>{disk.device_type}</td>
                    <td><span class="status {disk.state === 'ok' ? 'green' : disk.state === 'fail' ? 'red' : 'yellow'}">{disk.smart_status}</span></td>
                    <td>
                      <div class="row-actions">
                        <button on:click={() => startSmartTest(disk, 'short')}>Short test</button>
                        <button on:click={() => startSmartTest(disk, 'long')}>Long test</button>
                        <button on:click={() => startSmartTest(disk, 'conveyance')}>Conveyance</button>
                        <button on:click={() => loadSmartTests(disk)}>History</button>
                      </div>
                    </td>
                  </tr>
                  {#if smartTestHistory[disk.name]?.length}
                    <tr>
                      <td colspan="6">
                        <table class="nested-table">
                          <tbody>
                            {#each smartTestHistory[disk.name] as test}
                              <tr>
                                <td>#{test.number}</td>
                                <td>{test.description}</td>
                                <td>{test.status}</td>
                                <td>{test.remaining}</td>
                                <td>{test.lifetime_hours}h</td>
                                <td>{test.lba_of_first_error}</td>
                              </tr>
                            {/each}
                          </tbody>
                        </table>
                      </td>
                    </tr>
                  {/if}
                {/each}
              </tbody>
            </table>
          </section>
        {/if}
      {:else if active === 'snapshots'}
        <section class="panel">
          <form class="inline" on:submit|preventDefault={createSnapshot}>
            <input bind:value={snapshotForm.dataset} placeholder="dataset" on:change={loadSnapshots} />
            <input bind:value={snapshotForm.name} placeholder="snapshot name" />
            <button>Create</button>
          </form>
          <table><tbody>{#each snapshots as snap}<tr><td>{snap.name}</td><td>{snap.used}</td><td><button on:click={() => rollbackSnapshot(snap.name)}>Rollback</button><button on:click={() => deleteSnapshot(snap.name)}>Delete</button></td></tr>{/each}</tbody></table>
          <div class="subpanel">
            <h2>Clone and diff</h2>
            <form class="inline" on:submit|preventDefault={cloneSnapshot}>
              <select bind:value={snapshotCloneForm.snapshot}>
                <option value="">Select snapshot</option>
                {#each snapshots as snap}<option value={snap.name}>{snap.name}</option>{/each}
              </select>
              <input bind:value={snapshotCloneForm.target_dataset} placeholder="clone dataset" />
              <button disabled={!snapshotCloneForm.snapshot}>Clone</button>
            </form>
            <form class="inline" on:submit|preventDefault={loadSnapshotDiff}>
              <select bind:value={snapshotDiffForm.snapshot}>
                <option value="">Base snapshot</option>
                {#each snapshots as snap}<option value={snap.name}>{snap.name}</option>{/each}
              </select>
              <input bind:value={snapshotDiffForm.to_snapshot} placeholder="optional target snapshot" />
              <button disabled={!snapshotDiffForm.snapshot}>Diff</button>
            </form>
            {#if snapshotDiff.length}
              <table>
                <tbody>
                  {#each snapshotDiff as item}
                    <tr>
                      <td>{item.change}</td>
                      <td>{item.file_type || '-'}</td>
                      <td>{item.path}</td>
                      <td>{item.timestamp || ''}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {:else}
              <p class="empty">No diff loaded</p>
            {/if}
          </div>
          <div class="subpanel">
            <h2>Snapshot tasks</h2>
            <form class="inline" on:submit|preventDefault={createSnapshotTask}>
              <input bind:value={snapshotTaskForm.dataset} placeholder="dataset" />
              <input bind:value={snapshotTaskForm.prefix} placeholder="prefix" />
              <select bind:value={snapshotTaskForm.cadence}>
                <option value="hourly">hourly</option>
                <option value="daily">daily</option>
                <option value="weekly">weekly</option>
                <option value="monthly">monthly</option>
              </select>
              <input bind:value={snapshotTaskForm.retention_count} type="number" min="1" max="10000" placeholder="keep" />
              <label class="check"><input type="checkbox" bind:checked={snapshotTaskForm.enabled} /> Enabled</label>
              <button>Save task</button>
            </form>
            <table>
              <tbody>
                {#each snapshotTasks as task}
                  <tr>
                    <td>{task.dataset}</td>
                    <td>{task.prefix}</td>
                    <td>{task.cadence}</td>
                    <td>keep {task.retention_count}</td>
                    <td>{task.enabled ? 'enabled' : 'disabled'}</td>
                    <td>{task.last_run_at || 'never run'}</td>
                    <td><button disabled={!task.enabled} on:click={() => runSnapshotTask(task.id)}>Run now</button><button on:click={() => deleteSnapshotTask(task.id, task.prefix)}>Delete</button></td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          <div class="subpanel">
            <h2>Replication tasks</h2>
            <form class="inline" on:submit|preventDefault={createReplicationTask}>
              <input bind:value={replicationTaskForm.source_dataset} placeholder="source dataset" />
              <input bind:value={replicationTaskForm.destination_dataset} placeholder="destination dataset" />
              <select bind:value={replicationTaskForm.mode}>
                <option value="local">local</option>
                <option value="remote">remote</option>
              </select>
              <input bind:value={replicationTaskForm.remote_host} placeholder="remote host" disabled={replicationTaskForm.mode === 'local'} />
              <input bind:value={replicationTaskForm.remote_user} placeholder="remote user" disabled={replicationTaskForm.mode === 'local'} />
              <select bind:value={replicationTaskForm.cadence}>
                <option value="hourly">hourly</option>
                <option value="daily">daily</option>
                <option value="weekly">weekly</option>
                <option value="monthly">monthly</option>
              </select>
              <input bind:value={replicationTaskForm.retention_count} type="number" min="1" max="10000" placeholder="keep" />
              <label class="check"><input type="checkbox" bind:checked={replicationTaskForm.enabled} /> Enabled</label>
              <button>Save replication</button>
            </form>
            <table>
              <tbody>
                {#each replicationTasks as task}
                  <tr>
                    <td>{task.source_dataset}</td>
                    <td>{task.destination_dataset}</td>
                    <td>{task.mode}</td>
                    <td>{task.remote_host || 'local'}</td>
                    <td>{task.cadence}</td>
                    <td>keep {task.retention_count}</td>
                    <td>{task.enabled ? 'enabled' : 'disabled'}</td>
                    <td>{task.last_run_at || 'never run'}</td>
                    <td><button disabled={!task.enabled} on:click={() => runReplicationTask(task.id)}>Run now</button><button on:click={() => deleteReplicationTask(task.id, task.source_dataset)}>Delete</button></td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          <form class="inline restore-search" on:submit|preventDefault={() => snapshotFileSnapshot && searchSnapshotFiles(snapshotFileSnapshot)}>
            <input bind:value={snapshotFileSearch} placeholder="file search in selected snapshot" />
            <select bind:value={snapshotFileSnapshot} on:change={(event) => event.currentTarget.value && searchSnapshotFiles(event.currentTarget.value)}>
              <option value="">Select snapshot</option>
              {#each snapshots as snap}<option value={snap.name}>{snap.name}</option>{/each}
            </select>
            <button disabled={!snapshotFileSnapshot}>Search files</button>
          </form>
          {#if snapshotFiles.length}
            <div class="restore-list">
              {#each snapshotFiles as file}
                <label class="check"><input type="checkbox" checked={!!selectedSnapshotFiles[file.path]} on:change={() => toggleSnapshotFile(file.path)} /> {file.path}</label>
              {/each}
            </div>
            <div class="actions">
              <button on:click={() => snapshotFileSnapshot && restoreSnapshotFiles(snapshotFileSnapshot)}>Restore selected</button>
            </div>
          {/if}
        </section>
      {:else if active === 'shares'}
        <section class="split">
          <div class="panel">
            <h2>Samba</h2>
            <form class="stack" on:submit|preventDefault={saveSambaSettings}>
              <input bind:value={sambaSettings.workgroup} placeholder="workgroup" />
              <input bind:value={sambaSettings.server_string} placeholder="server string" />
              <input bind:value={sambaSettings.netbios_name} placeholder="netbios name" />
              <select bind:value={sambaSettings.security}>
                <option value="user">user</option>
                <option value="ads">ads</option>
                <option value="domain">domain</option>
              </select>
              <select bind:value={sambaSettings.map_to_guest}>
                <option value="Bad User">Bad User</option>
                <option value="Bad Password">Bad Password</option>
                <option value="Never">Never</option>
              </select>
              <input bind:value={sambaSettings.log_level} placeholder="log level" />
              <button>Save server settings</button>
            </form>
            <form class="stack" on:submit|preventDefault={saveSamba}>
              <input bind:value={sambaForm.name} placeholder="share name" />
              <input bind:value={sambaForm.path} placeholder="/mnt/tank/share" />
              <input bind:value={sambaForm.allowed_users} placeholder="allowed users, comma separated" />
              <label class="check"><input type="checkbox" bind:checked={sambaForm.readonly} /> Read only</label>
              <button>Save Samba share</button>
            </form>
            <ul class="share-list">{#each sambaShares as share}<li><span>{share.name} {share.path}</span><button on:click={() => deleteSamba(share.id, share.name)}>Delete</button></li>{/each}</ul>
          </div>
          <div class="panel">
            <h2>Samba users</h2>
            <form class="stack" on:submit|preventDefault={saveSambaUser}>
              <input bind:value={sambaUserForm.username} placeholder="storage username" />
              <input bind:value={sambaUserForm.password} type="password" placeholder="samba password" />
              <label class="check"><input type="checkbox" bind:checked={sambaUserForm.enabled} /> Enabled</label>
              <button>Save Samba user</button>
            </form>
            <ul class="share-list">{#each sambaUsers as row}<li><span>{row.username} {row.enabled ? 'enabled' : 'disabled'}</span><button on:click={() => deleteSambaUser(row.username)}>Delete</button></li>{/each}</ul>
          </div>
          <div class="panel">
            <h2>NFS</h2>
            <form class="stack" on:submit|preventDefault={saveNfs}>
              <input bind:value={nfsForm.path} placeholder="/mnt/tank/share" />
              <input bind:value={nfsForm.clients} placeholder="192.168.1.0/24" />
              <input bind:value={nfsForm.options} placeholder="-maproot=root" />
              <button>Save NFS export</button>
            </form>
            <ul class="share-list">{#each nfsShares as share}<li><span>{share.path} {share.clients}</span><button on:click={() => deleteNfs(share.id, share.path)}>Delete</button></li>{/each}</ul>
          </div>
          <div class="panel">
            <h2>iSCSI</h2>
            <form class="stack" on:submit|preventDefault={saveIscsi}>
              <input bind:value={iscsiForm.name} placeholder="target IQN" />
              <input bind:value={iscsiForm.portal_group} placeholder="portal group" />
              <input bind:value={iscsiForm.initiator_name} placeholder="initiator name, optional" />
              <input bind:value={iscsiForm.auth_group} placeholder="auth group" />
              <input bind:value={iscsiForm.extent_name} placeholder="extent name" />
              <input bind:value={iscsiForm.path} placeholder="/dev/zvol/tank/iscsi/disk0" />
              <input bind:value={iscsiForm.size} placeholder="size, optional" />
              <input bind:value={iscsiForm.lun_id} type="number" min="0" max="1023" placeholder="LUN" />
              <label class="check"><input type="checkbox" bind:checked={iscsiForm.readonly} /> Read only</label>
              <button>Save iSCSI target</button>
            </form>
            <ul class="share-list">{#each iscsiTargets as target}<li><span>{target.name} LUN {target.lun_id} {target.path}</span><button on:click={() => deleteIscsi(target.id, target.name)}>Delete</button></li>{/each}</ul>
          </div>
        </section>
      {:else if active === 'services'}
        <section class="panel">
          <div class="toolbar">
            <h2>System</h2>
            <button on:click={loadSystemReport}>Refresh</button>
          </div>
          {#if systemReport}
            <dl class="system-grid">
              <dt>Host</dt><dd>{systemReport.hostname}</dd>
              <dt>OS</dt><dd>{systemReport.os} {systemReport.release}</dd>
              <dt>Uptime</dt><dd>{runtimeLabel(systemReport.uptime_seconds)}</dd>
              <dt>CPU</dt><dd>{systemReport.cpu_model || 'unknown'}</dd>
              <dt>Cores</dt><dd>{systemReport.cpu_cores || 'unknown'}</dd>
              <dt>Memory</dt><dd>{bytesLabel(systemReport.memory_bytes)}</dd>
              <dt>Free memory</dt><dd>{bytesLabel(systemReport.memory_free_bytes)}</dd>
              <dt>Swap</dt><dd>{bytesLabel(systemReport.swap_total_bytes)}</dd>
              <dt>Load</dt><dd>{Array.isArray(systemReport.load_average) ? systemReport.load_average.join(', ') : 'unknown'}</dd>
            </dl>
          {:else}
            <p class="empty">System report unavailable</p>
          {/if}
        </section>
        <section class="panel services-grid">
          <div class="toolbar">
            <h2>Network</h2>
            <button on:click={loadNetworkInterfaces}>Refresh</button>
          </div>
          {#if networkInterfaces.length}
            <table>
              <tbody>
                {#each networkInterfaces as iface}
                  <tr>
                    <td>{iface.name}</td>
                    <td><span class="status {iface.status === 'active' ? 'green' : 'yellow'}">{iface.status}</span></td>
                    <td>{iface.mac || '-'}</td>
                    <td>{Array.isArray(iface.ipv4) && iface.ipv4.length ? iface.ipv4.join(', ') : '-'}</td>
                    <td>{Array.isArray(iface.ipv6) && iface.ipv6.length ? iface.ipv6.join(', ') : '-'}</td>
                    <td>mtu {iface.mtu || '-'}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {:else}
            <p class="empty">No network interfaces loaded</p>
          {/if}
          <form class="inline network-config" on:submit|preventDefault={saveNetworkConfig}>
            <input bind:value={networkConfigForm.name} placeholder="interface" />
            <select bind:value={networkConfigForm.mode}>
              <option value="dhcp">DHCP</option>
              <option value="static">Static IPv4</option>
            </select>
            <input bind:value={networkConfigForm.ipv4_address} disabled={networkConfigForm.mode !== 'static'} placeholder="IPv4 address" />
            <input bind:value={networkConfigForm.netmask} disabled={networkConfigForm.mode !== 'static'} placeholder="netmask" />
            <input bind:value={networkConfigForm.gateway} placeholder="default gateway, optional" />
            <button>Apply network config</button>
          </form>
          {#if networkConfigs.length}
            <table>
              <tbody>
                {#each networkConfigs as config}
                  <tr>
                    <td>{config.name}</td>
                    <td>{config.mode}</td>
                    <td>{config.ipv4_address || '-'}</td>
                    <td>{config.netmask || '-'}</td>
                    <td>{config.gateway || '-'}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
          <form class="inline network-config" on:submit|preventDefault={saveDnsConfig}>
            <input bind:value={dnsConfigForm.nameservers} placeholder="DNS nameservers" />
            <input bind:value={dnsConfigForm.search_domains} placeholder="search domains, optional" />
            <button>Apply DNS config</button>
          </form>
          {#if Array.isArray(dnsConfig.nameservers) && dnsConfig.nameservers.length}
            <table>
              <tbody>
                <tr>
                  <td>DNS</td>
                  <td>{dnsConfig.nameservers.join(', ')}</td>
                  <td>{Array.isArray(dnsConfig.search_domains) && dnsConfig.search_domains.length ? dnsConfig.search_domains.join(', ') : '-'}</td>
                </tr>
              </tbody>
            </table>
          {/if}
          <form class="inline network-config" on:submit|preventDefault={saveStaticRoute}>
            <input bind:value={staticRouteForm.destination} placeholder="route destination" />
            <input bind:value={staticRouteForm.gateway} placeholder="route gateway" />
            <input bind:value={staticRouteForm.description} placeholder="route description, optional" />
            <button>Apply static route</button>
          </form>
          {#if staticRoutes.length}
            <table>
              <tbody>
                {#each staticRoutes as route}
                  <tr>
                    <td>{route.destination}</td>
                    <td>{route.gateway}</td>
                    <td>{route.description || '-'}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </section>
        <section class="panel">
          <div class="toolbar">
            <h2>UPS</h2>
            <button on:click={loadUpsStatus}>Refresh</button>
          </div>
          {#if upsStatus}
            <div class="ups-grid">
              <span class="status {upsStatus.state === 'online' ? 'green' : upsStatus.state === 'on_battery' ? 'yellow' : 'red'}">{upsStatus.state}</span>
              <dl>
                <dt>Model</dt><dd>{upsStatus.model}</dd>
                <dt>Status</dt><dd>{upsStatus.status}</dd>
                <dt>Charge</dt><dd>{upsStatus.charge_percent ?? 'unknown'}%</dd>
                <dt>Runtime</dt><dd>{runtimeLabel(upsStatus.runtime_seconds)}</dd>
                <dt>Load</dt><dd>{upsStatus.load_percent ?? 'unknown'}%</dd>
                <dt>Input</dt><dd>{upsStatus.input_voltage || 'unknown'}</dd>
              </dl>
            </div>
          {:else}
            <p class="empty">UPS status unavailable</p>
          {/if}
          <form class="inline ups-policy" on:submit|preventDefault={saveUpsPolicy}>
            <label class="check"><input type="checkbox" bind:checked={upsPolicy.enabled} /> Policy enabled</label>
            <input bind:value={upsPolicy.low_charge_percent} type="number" min="0" max="100" placeholder="low charge %" />
            <input bind:value={upsPolicy.min_runtime_seconds} type="number" min="0" max="86400" placeholder="minimum runtime seconds" />
            <input bind:value={upsPolicy.shutdown_command} placeholder="shutdown command" />
            <button>Save UPS policy</button>
          </form>
          <div class="actions">
            <button disabled={!upsPolicy.enabled} on:click={executeUpsShutdown}>Execute UPS shutdown</button>
          </div>
        </section>
        <section class="panel">
          <div class="toolbar">
            <h2>Directory service</h2>
            <button on:click={loadDirectoryService}>Refresh</button>
          </div>
          <form class="stack directory-form" on:submit|preventDefault={saveDirectoryService}>
            <label class="check"><input type="checkbox" bind:checked={directoryService.enabled} /> Enabled</label>
            <select bind:value={directoryService.provider}>
              <option value="ldap">LDAP</option>
              <option value="active_directory">Active Directory</option>
            </select>
            <input bind:value={directoryService.domain} placeholder="directory domain" />
            <input bind:value={directoryService.uri} placeholder="ldap://directory.example.test" />
            <input bind:value={directoryService.base_dn} placeholder="dc=example,dc=test" />
            <input bind:value={directoryService.bind_dn} placeholder="bind DN, optional" />
            <label class="check"><input type="checkbox" bind:checked={directoryService.tls} /> TLS required</label>
            <button>Save directory service</button>
          </form>
        </section>
        <section class="grid services-grid">
          {#each services as svc}
            <article class="card">
              <h2>{svc.label}</h2>
              <span class="status {svc.color}">{svc.status}</span>
              <div class="actions"><button on:click={() => serviceAction(svc.name, 'start')}>Start</button><button on:click={() => serviceAction(svc.name, 'stop')}>Stop</button><button on:click={() => serviceAction(svc.name, 'restart')}>Restart</button></div>
            </article>
          {/each}
        </section>
      {:else if active === 'alerts'}
        <section class="split">
          <div class="panel">
            <div class="toolbar">
              <h2>Alerts</h2>
              <button on:click={loadAlerts}>Refresh</button>
            </div>
            {#if alerts.length}
              <table>
                <tbody>
                  {#each alerts as item}
                    <tr>
                      <td><span class="status {item.severity === 'critical' ? 'red' : 'yellow'}">{item.severity}</span></td>
                      <td>{item.category}</td>
                      <td>{item.target}</td>
                      <td>{item.message}</td>
                      <td>{item.created_at}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {:else}
              <p class="empty">No active alerts</p>
            {/if}
          </div>
          <div class="panel">
            <h2>Notifications</h2>
            <form class="stack" on:submit|preventDefault={saveAlertNotifications}>
              <label class="check"><input type="checkbox" bind:checked={alertNotifications.enabled} /> Enabled</label>
              <select bind:value={alertNotifications.min_severity}>
                <option value="warning">warning</option>
                <option value="critical">critical</option>
              </select>
              <input bind:value={alertNotifications.webhook_url} placeholder="webhook URL" />
              <input bind:value={alertNotifications.email_to} placeholder="email recipient" />
              <input bind:value={alertNotifications.smtp_host} placeholder="SMTP host" />
              <input bind:value={alertNotifications.smtp_port} type="number" min="1" max="65535" placeholder="SMTP port" />
              <input bind:value={alertNotifications.smtp_from} placeholder="SMTP sender" />
              <select bind:value={alertNotifications.smtp_tls}>
                <option value="none">SMTP TLS: none</option>
                <option value="starttls">SMTP TLS: STARTTLS</option>
                <option value="tls">SMTP TLS: implicit TLS</option>
              </select>
              <input bind:value={alertNotifications.smtp_username} placeholder="SMTP username" />
              <input bind:value={alertNotifications.smtp_password} type="password" placeholder="SMTP password" />
              <div class="actions">
                <button>Save notifications</button>
                <button type="button" disabled={!alertNotifications.enabled} on:click={testAlertNotifications}>Test</button>
              </div>
            </form>
            <div class="subpanel">
              <div class="toolbar">
                <h2>Delivery history</h2>
                <button on:click={loadAlertNotificationHistory}>Refresh</button>
              </div>
              {#if alertNotificationHistory.length}
                <table>
                  <tbody>
                    {#each alertNotificationHistory as item}
                      <tr>
                        <td>{item.created_at}</td>
                        <td>{item.channel}</td>
                        <td><span class="status {item.severity === 'critical' ? 'red' : 'yellow'}">{item.severity}</span></td>
                        <td>{item.target}</td>
                        <td>{item.result}</td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              {:else}
                <p class="empty">No notification attempts</p>
              {/if}
            </div>
          </div>
        </section>
      {:else if active === 'logs'}
        <section class="panel">
          <form class="inline" on:submit|preventDefault={loadLogs}>
            <input bind:value={logFilters.service} placeholder="service" />
            <input bind:value={logFilters.severity} placeholder="severity" />
            <input bind:value={logFilters.search} placeholder="search" />
            <input bind:value={logFilters.from} type="datetime-local" />
            <input bind:value={logFilters.to} type="datetime-local" />
            <button>Filter</button>
          </form>
          <table><tbody>{#each logs as row}<tr><td>{row.timestamp}</td><td>{row.service}</td><td>{row.severity}</td><td>{row.message}</td></tr>{/each}</tbody></table>
        </section>
      {:else if active === 'audit'}
        <section class="split">
          <div class="panel">
            <h2>Audit events</h2>
            <table><tbody>{#each audit as row}<tr><td>{row.created_at}</td><td>{row.actor}</td><td>{row.category}</td><td>{row.target}</td><td>{row.result}</td><td>{row.message}</td></tr>{/each}</tbody></table>
          </div>
          <div class="panel">
            <h2>Helper history</h2>
            <table><tbody>{#each helperHistory as row}<tr><td>{row.created_at}</td><td>{row.actor}</td><td>{row.ok ? 'ok' : 'error'}</td><td class="mono">{row.operation}</td><td>{row.message}</td></tr>{/each}</tbody></table>
          </div>
        </section>
      {:else if active === 'users'}
        <section class="panel">
          <h2>Dashboard users</h2>
          <form class="inline" on:submit|preventDefault={createUser}>
            <input bind:value={userForm.username} placeholder="username" />
            <input bind:value={userForm.password} type="password" placeholder="temporary password" />
            <label class="check"><input type="checkbox" bind:checked={userForm.is_admin} /> Admin</label>
            <button>Create user</button>
          </form>
          <table>
            <tbody>
              {#each users as row}
                <tr>
                  <td>{row.username}</td>
                  <td>{row.is_admin ? 'admin' : 'viewer'}</td>
                  <td>{row.must_change_password ? 'password pending' : 'active'}</td>
                  <td>
                    <div class="row-actions">
                      <button on:click={() => setUserRole(row.id, !row.is_admin)}>{row.is_admin ? 'Demote' : 'Promote'}</button>
                      <button on:click={() => resetUserPassword(row.id, row.username)}>Reset password</button>
                      <button on:click={() => deleteUser(row.id, row.username)} disabled={row.id === user.id}>Delete</button>
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
          <div class="subpanel">
            <h2>Local users</h2>
            <form class="inline" on:submit|preventDefault={saveLocalUser}>
              <input bind:value={localUserForm.username} placeholder="username" />
              <input bind:value={localUserForm.full_name} placeholder="full name" />
              <input bind:value={localUserForm.shell} placeholder="/bin/sh" />
              <input bind:value={localUserForm.home} placeholder="home, optional" />
              <input bind:value={localUserForm.groups} placeholder="groups, comma separated" />
              <input bind:value={localUserForm.password} type="password" placeholder="password, optional" />
              <label class="check"><input type="checkbox" bind:checked={localUserForm.create_home} /> Home</label>
              <button>Save local user</button>
            </form>
            <table>
              <tbody>
                {#each localUsers as row}
                  <tr>
                    <td>{row.username}</td>
                    <td>{row.uid}</td>
                    <td>{row.home}</td>
                    <td>{row.shell}</td>
                    <td><button on:click={() => deleteLocalUser(row.username)}>Delete</button></td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          <div class="subpanel">
            <h2>Local groups</h2>
            <form class="inline" on:submit|preventDefault={saveLocalGroup}>
              <input bind:value={localGroupForm.name} placeholder="group name" />
              <input bind:value={localGroupForm.members} placeholder="members, comma separated" />
              <button>Save local group</button>
            </form>
            <table>
              <tbody>
                {#each localGroups as row}
                  <tr>
                    <td>{row.name}</td>
                    <td>{row.gid}</td>
                    <td>{Array.isArray(row.members) ? row.members.join(', ') : ''}</td>
                    <td><button on:click={() => deleteLocalGroup(row.name)}>Delete</button></td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>
      {:else if active === 'config'}
        <section class="panel">
          <div class="toolbar">
            <h2>Configuration</h2>
            <button on:click={exportConfig}>Export</button>
          </div>
          <form class="stack" on:submit|preventDefault={importConfig}>
            <textarea bind:value={configBackupText} rows="18" placeholder="configuration backup JSON"></textarea>
            <label class="check"><input type="checkbox" bind:checked={configImportReplace} /> Replace existing saved configuration</label>
            <button>Import</button>
          </form>
        </section>
      {/if}
    </main>
  </div>
{/if}
