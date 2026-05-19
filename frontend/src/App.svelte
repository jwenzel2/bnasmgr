<script>
  const apiBase = '';
  let token = localStorage.getItem('bnasmgr_token') || '';
  let user = null;
  let error = '';
  let active = 'storage';
  let loginForm = { username: 'admin', password: 'admin' };
  let passwordForm = { current_password: 'admin', new_password: '' };
  let storage = { pools: [], datasets: [] };
  let snapshots = [];
  let snapshotTasks = [];
  let services = [];
  let sambaShares = [];
  let sambaSettings = { workgroup: 'WORKGROUP', server_string: 'bnasmgr NAS', netbios_name: 'BNASMGR', security: 'user', map_to_guest: 'Bad User', log_level: '1' };
  let sambaUsers = [];
  let nfsShares = [];
  let logs = [];
  let audit = [];
  let helperHistory = [];
  let users = [];
  let snapshotForm = { dataset: 'tank/media', name: '' };
  let snapshotTaskForm = { dataset: 'tank/media', prefix: 'auto', cadence: 'daily', retention_count: 14, enabled: true };
  let snapshotFileSnapshot = '';
  let snapshotFileSearch = '';
  let snapshotFiles = [];
  let selectedSnapshotFiles = {};
  let sambaForm = { name: '', path: '', allowed_users: '', readonly: false };
  let sambaUserForm = { username: '', password: '', enabled: true };
  let nfsForm = { path: '', clients: '', options: '-maproot=root' };
  let userForm = { username: '', password: '', is_admin: true };
  let logFilters = { service: '', severity: '', search: '', from: '', to: '' };

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
    await Promise.all([loadStorage(), loadSnapshots(), loadSnapshotTasks(), loadServices(), loadShares(), loadLogs(), loadAudit(), loadHelperHistory(), loadUsers()]);
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

  async function loadSnapshots() {
    snapshots = await request(`/api/snapshots?dataset=${encodeURIComponent(snapshotForm.dataset)}`);
    snapshotFileSnapshot = snapshots[0]?.name || '';
    snapshotFiles = [];
    selectedSnapshotFiles = {};
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

  async function serviceAction(service, action) {
    await request(`/api/services/${service}/${action}`, { method: 'POST' });
    await loadServices();
  }

  async function loadShares() {
    [sambaShares, sambaSettings, sambaUsers, nfsShares] = await Promise.all([request('/api/shares/samba'), request('/api/shares/samba/settings'), request('/api/shares/samba/users'), request('/api/shares/nfs')]);
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

  async function loadLogs() {
    const params = new URLSearchParams(Object.entries(logFilters).filter(([, v]) => v).map(([key, value]) => {
      if ((key === 'from' || key === 'to') && value) return [key, new Date(value).toISOString()];
      return [key, value];
    }));
    logs = await request(`/api/logs?${params}`);
  }

  async function loadAudit() {
    audit = await request('/api/audit');
  }

  async function loadHelperHistory() {
    helperHistory = await request('/api/audit/helper-history');
  }

  async function loadUsers() {
    users = await request('/api/users');
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
      {#each ['storage', 'snapshots', 'shares', 'services', 'logs', 'audit', 'users'] as tab}
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
              <dl><dt>Used</dt><dd>{ds.used}</dd><dt>Available</dt><dd>{ds.available}</dd><dt>Quota</dt><dd>{ds.quota || 'none'}</dd><dt>Mount</dt><dd>{ds.mountpoint}</dd><dt>Snapshots</dt><dd>{ds.snapshots}</dd></dl>
              <form class="quota-form" on:submit|preventDefault={(event) => setQuota(ds.name, event)}>
                <input name="quota" value={ds.quota || ''} placeholder="quota, e.g. 2T or none" />
                <button>Set quota</button>
              </form>
              <span class:green={ds.health === 'online'} class="status">{ds.health}</span>
            </article>
          {/each}
        </section>
      {:else if active === 'snapshots'}
        <section class="panel">
          <form class="inline" on:submit|preventDefault={createSnapshot}>
            <input bind:value={snapshotForm.dataset} placeholder="dataset" on:change={loadSnapshots} />
            <input bind:value={snapshotForm.name} placeholder="snapshot name" />
            <button>Create</button>
          </form>
          <table><tbody>{#each snapshots as snap}<tr><td>{snap.name}</td><td>{snap.used}</td><td><button on:click={() => rollbackSnapshot(snap.name)}>Rollback</button><button on:click={() => deleteSnapshot(snap.name)}>Delete</button></td></tr>{/each}</tbody></table>
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
        </section>
      {:else if active === 'services'}
        <section class="grid">
          {#each services as svc}
            <article class="card">
              <h2>{svc.label}</h2>
              <span class="status {svc.color}">{svc.status}</span>
              <div class="actions"><button on:click={() => serviceAction(svc.name, 'start')}>Start</button><button on:click={() => serviceAction(svc.name, 'stop')}>Stop</button><button on:click={() => serviceAction(svc.name, 'restart')}>Restart</button></div>
            </article>
          {/each}
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
        </section>
      {/if}
    </main>
  </div>
{/if}
