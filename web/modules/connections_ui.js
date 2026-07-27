import {
    collectSafeFieldValues,
    normalizeTone,
    renderSafeField,
} from './ui_helpers.js';
import { escapeHtmlAttr, escapeHtmlText } from './utils.js';

const CONNECTION_FIELDS = Object.freeze([
    { name: 'name', label: 'Name', type: 'text', required: true, placeholder: 'Production' },
    { name: 'ssh_alias', label: 'SSH alias', type: 'text', required: true, placeholder: 'production' },
]);
const AUTH_FIELDS = Object.freeze([
    {
        name: 'password',
        label: 'Network Password',
        type: 'password',
        required: true,
        help: 'Used once to create an HttpOnly owner session; it is not retained by this page.',
    },
]);
const FIELD_OPTIONS = Object.freeze({
    fieldClass: 'form-field',
    helpClass: 'settings-inline-note',
});

export function isSelectableRemoteConnection(row) {
    if (!row || row.lifecycle !== 'active') return false;
    const status = String(row.status || 'unknown');
    return (
        status === 'ready'
        && row.bootstrap_compatible === true
        && row.health_fresh === true
    );
}

export function connectionStatusCopy(row = {}) {
    const status = String(row.status || (row.lifecycle === 'retired' ? 'disconnected' : 'unknown'));
    const phase = String(row.phase || '');
    const error = String(row.error_code || '');
    const warningCodes = (Array.isArray(row.warnings) ? row.warnings : [])
        .filter((warning) => warning && typeof warning === 'object')
        .slice(0, 4)
        .map((warning) => String(warning.code || 'ssh_warning'));
    return [
        status,
        phase && `phase: ${phase}`,
        error && `error: ${error}`,
        ...warningCodes.map((code) => `warning: ${code}`),
    ]
        .filter(Boolean)
        .join(' · ');
}

function observedHostId(payload) {
    for (const source of [
        payload,
        payload?.handshake,
        payload?.diagnostic,
    ]) {
        const value = String(source?.host_id || source?.observed_host_id || '').trim();
        if (value) return value;
    }
    return '';
}

function statusTone(row) {
    const status = String(row?.status || 'unknown');
    if (status === 'ready') return 'ok';
    if (status === 'connecting') return 'info';
    if (status === 'degraded' || status === 'disconnected') return 'warn';
    return 'muted';
}

function connectionDetails(row) {
    const facts = [
        row.expected_host_id && ['Pinned host identity', row.expected_host_id],
        row.platform && ['Platform', row.platform],
        row.architecture && ['Architecture', row.architecture],
        row.build && ['Executor build', row.build],
        ['Bootstrap compatible (this run)', row.bootstrap_compatible === true ? 'yes' : 'no'],
        ['Health fresh', row.health_fresh === true ? 'yes' : 'no'],
        row.completion && ['Completion', row.completion],
        row.action && ['Next action', row.action],
    ].filter(Boolean);
    const diagnostic = row.diagnostic && typeof row.diagnostic === 'object'
        ? JSON.stringify(row.diagnostic, null, 2)
        : '';
    const logRefs = Array.isArray(row.log_refs) && row.log_refs.length
        ? JSON.stringify(row.log_refs, null, 2)
        : '';
    const warnings = Array.isArray(row.warnings) && row.warnings.length
        ? JSON.stringify(row.warnings.slice(0, 4), null, 2)
        : '';
    if (!facts.length && !diagnostic && !logRefs && !warnings) return '';
    return `
        <details class="connection-details">
            <summary>Details and logs</summary>
            ${facts.length ? `<dl>${facts.map(([label, value]) => `
                <div><dt>${escapeHtmlText(label)}</dt><dd><code>${escapeHtmlText(value)}</code></dd></div>
            `).join('')}</dl>` : ''}
            ${diagnostic ? `<h4>Diagnostic</h4><pre>${escapeHtmlText(diagnostic)}</pre>` : ''}
            ${logRefs ? `<h4>Log references</h4><pre>${escapeHtmlText(logRefs)}</pre>` : ''}
            ${warnings ? `<h4>Warnings</h4><pre>${escapeHtmlText(warnings)}</pre>` : ''}
        </details>
    `;
}

function connectionRow(row, loading) {
    const retired = row.lifecycle === 'retired';
    const disabled = loading ? ' disabled' : '';
    return `
        <article class="connection-row" data-connection-id="${escapeHtmlAttr(row.id)}">
            <div class="connection-row-body">
                <div class="connection-row-main">
                    <strong>${escapeHtmlText(row.name || row.id)}</strong>
                    <code>${escapeHtmlText(row.ssh_alias)}</code>
                    <span class="connection-state" data-tone="${statusTone(row)}">${escapeHtmlText(connectionStatusCopy(row))}</span>
                </div>
                ${connectionDetails(row)}
            </div>
            <div class="connection-row-actions">
                ${retired ? '<span class="settings-inline-note">Retired</span>' : `
                    <button type="button" class="btn btn-default btn-sm" data-conn-action="test"${disabled}>Test</button>
                    <button type="button" class="btn btn-secondary btn-sm" data-conn-action="bootstrap"${disabled}>Bootstrap</button>
                    <button type="button" class="btn btn-default btn-sm" data-conn-action="reconnect"${disabled}>Reconnect</button>
                    <button type="button" class="btn btn-default btn-sm" data-conn-action="retrust"${disabled}>Retrust host…</button>
                    <button type="button" class="btn btn-danger btn-sm" data-conn-action="retire"${disabled}>Retire</button>
                `}
            </div>
        </article>
    `;
}

export function initConnectionsUI({ root, apiClient, ws } = {}) {
    const host = root?.querySelector?.('#settings-connections-root');
    if (!host) return;
    let connections = [];
    let loading = false;
    let accessState = 'unknown';
    let requestRevision = 0;
    let liveRevision = 0;
    const liveOverrides = new Map();

    function authMarkup() {
        if (accessState === 'required') {
            return `
                <form class="connection-auth-form" data-conn-auth>
                    ${renderSafeField(AUTH_FIELDS[0], {}, FIELD_OPTIONS)}
                    <button type="submit" class="btn btn-primary"${loading ? ' disabled' : ''}>Unlock Connections</button>
                </form>
            `;
        }
        if (accessState === 'unconfigured') {
            return `
                <div class="settings-inline-note" role="note">
                    Configure a Network Password in Settings → Providers (or
                    <code>OUROBOROS_NETWORK_PASSWORD</code> in the server environment),
                    then restart Ouroboros. The value is never shown here.
                </div>
            `;
        }
        return '';
    }

    function managementMarkup() {
        if (accessState !== 'ready') return '';
        return `
            <form class="connections-add-form" data-conn-add>
                ${CONNECTION_FIELDS.map((field) => renderSafeField(field, {}, {
                    ...FIELD_OPTIONS,
                    disabled: loading,
                })).join('')}
                <button type="submit" class="btn btn-primary"${loading ? ' disabled' : ''}>Add</button>
            </form>
            <div class="connections-list">
                ${connections.length
                    ? connections.map((row) => connectionRow(row, loading)).join('')
                    : '<div class="settings-inline-note">No saved SSH connections.</div>'}
            </div>
        `;
    }

    function render(message = '', tone = 'muted') {
        host.innerHTML = `
            <section class="settings-card connections-card" aria-busy="${loading ? 'true' : 'false'}">
                <div class="settings-card-head">
                    <div>
                        <h3>SSH Connections</h3>
                        <div class="settings-section-copy">
                            Add a name and an SSH config alias such as <code>production</code>.
                            Test verifies transport and host identity; Bootstrap installs or
                            upgrades the compatible remote executor. Password, MFA and OpenSSH
                            host-trust prompts must be completed in a normal terminal.
                        </div>
                    </div>
                    <button type="button" class="btn btn-default btn-sm" data-conn-refresh${loading ? ' disabled' : ''}>Refresh</button>
                </div>
                ${authMarkup()}
                ${managementMarkup()}
                <div class="settings-inline-status" data-tone="${normalizeTone(tone)}" data-conn-status aria-live="polite">${escapeHtmlText(message)}</div>
            </section>
        `;
        host.querySelector('[data-conn-refresh]')?.addEventListener('click', () => load());
        host.querySelector('[data-conn-auth]')?.addEventListener('submit', authenticate);
        host.querySelector('[data-conn-add]')?.addEventListener('submit', async (event) => {
            event.preventDefault();
            if (loading) return;
            const values = collectSafeFieldValues(event.currentTarget, CONNECTION_FIELDS);
            await act(
                () => apiClient.connectionAdd({
                    name: String(values.name || '').trim(),
                    ssh_alias: String(values.ssh_alias || '').trim(),
                }),
                'Connection saved. Run Test, then Bootstrap before selecting it for a Project.',
                { phase: 'save' },
            );
        });
        host.querySelectorAll('[data-conn-action]').forEach((button) => {
            button.addEventListener('click', () => {
                if (loading) return;
                handleAction(
                    button.closest('[data-connection-id]')?.dataset.connectionId || '',
                    button.dataset.connAction,
                );
            });
        });
    }

    function mergePayload(payload, connectionId = '') {
        if (!payload || typeof payload !== 'object') return;
        const stored = payload.connection && typeof payload.connection === 'object'
            ? payload.connection
            : {};
        const id = String(stored.id || payload.connection_id || connectionId || '');
        if (!id) return;
        const publicLive = {};
        for (const key of [
            'status', 'phase', 'platform', 'architecture', 'build', 'completion',
            'bootstrap_compatible', 'health_fresh',
            'error_code', 'action', 'diagnostic', 'log_refs', 'warnings',
        ]) {
            if (Object.prototype.hasOwnProperty.call(payload, key)) publicLive[key] = payload[key];
        }
        const existing = connections.find((row) => row.id === id) || {};
        const merged = { ...existing, ...stored, ...publicLive, id };
        const previous = liveOverrides.get(id)?.fields || {};
        liveOverrides.set(id, {
            revision: ++liveRevision,
            fields: { ...previous, ...stored, ...publicLive },
        });
        const index = connections.findIndex((row) => row.id === id);
        if (index < 0) connections.push(merged);
        else connections[index] = merged;
    }

    async function authenticate(event) {
        event.preventDefault();
        if (loading) return;
        const values = collectSafeFieldValues(event.currentTarget, AUTH_FIELDS);
        const password = String(values.password || '');
        loading = true;
        render('Creating owner session…', 'info');
        try {
            await apiClient.ownerLogin(password);
            accessState = 'ready';
            await load('Owner session established.', 'ok');
        } catch (error) {
            loading = false;
            accessState = 'required';
            render(error?.body?.error || error?.message || String(error), 'warn');
        }
    }

    async function load(message = '', tone = 'muted') {
        const revision = ++requestRevision;
        const liveAtStart = liveRevision;
        loading = true;
        render(message || 'Loading connections…', tone);
        try {
            const data = await apiClient.connections();
            if (revision !== requestRevision) return;
            connections = (Array.isArray(data?.connections) ? data.connections : []).map((row) => {
                const override = liveOverrides.get(String(row.id || ''));
                const fields = override?.fields || {};
                const retainedDetails = {};
                for (const key of [
                    'platform', 'architecture', 'build', 'completion',
                    'bootstrap_compatible', 'health_fresh',
                    'diagnostic', 'log_refs', 'warnings',
                ]) {
                    if (!(key in row) && key in fields) retainedDetails[key] = fields[key];
                }
                return {
                    ...row,
                    ...retainedDetails,
                    ...(override?.revision > liveAtStart ? fields : {}),
                };
            });
            accessState = 'ready';
            loading = false;
            render(message, tone);
        } catch (error) {
            if (revision !== requestRevision) return;
            loading = false;
            const code = error?.body?.error_code || '';
            if (code === 'owner_auth_required') {
                connections = [];
                accessState = 'required';
                render('Enter the existing Network Password to unlock connection administration.', 'warn');
            } else if (code === 'owner_auth_not_configured') {
                connections = [];
                accessState = 'unconfigured';
                render('Owner authentication is not configured.', 'warn');
            } else {
                render(error?.body?.error || error?.message || String(error), 'warn');
            }
        }
    }

    async function act(operation, success, { connectionId = '', phase = 'connect' } = {}) {
        loading = true;
        if (connectionId) {
            mergePayload({ connection_id: connectionId, status: 'connecting', phase });
        }
        render(`Working · phase: ${phase}`, 'info');
        try {
            const result = await operation();
            mergePayload(result, connectionId);
            loading = false;
            render(success, 'ok');
        } catch (error) {
            mergePayload(error?.body, connectionId);
            loading = false;
            if (error?.body?.error_code === 'owner_auth_required') {
                accessState = 'required';
                connections = [];
            }
            render(
                `${error?.body?.error || error?.message || error}${error?.body?.action ? ` · Next: ${error.body.action}` : ''}`,
                'warn',
            );
        }
    }

    async function handleAction(connectionId, action) {
        const row = connections.find((item) => item.id === connectionId);
        if (!row) return;
        if (action === 'test') {
            await act(
                () => apiClient.connectionTest(connectionId),
                'Transport test passed. Run Bootstrap to make this connection selectable.',
                { connectionId, phase: 'connect' },
            );
        } else if (action === 'bootstrap') {
            await act(
                () => apiClient.connectionBootstrap(connectionId),
                'Remote executor is ready.',
                { connectionId, phase: 'bootstrap' },
            );
        } else if (action === 'reconnect') {
            await act(
                () => apiClient.connectionReconnect(connectionId),
                'Remote Project sessions reconnected and reconciled.',
                { connectionId, phase: 'reconcile' },
            );
        } else if (action === 'retire') {
            if (!confirm(`Retire “${row.name || row.id}”? Existing projects keep their binding, but no new work can start until they are rebound.`)) return;
            await act(
                () => apiClient.connectionRetire(connectionId),
                'Connection retired.',
                { connectionId, phase: 'retire' },
            );
        } else if (action === 'retrust') {
            let probe;
            loading = true;
            mergePayload({ connection_id: connectionId, status: 'connecting', phase: 'connect' });
            render('Testing the currently observed host identity…', 'info');
            try {
                probe = await apiClient.connectionTest(connectionId);
            } catch (error) {
                probe = error?.body || {};
            }
            mergePayload(probe, connectionId);
            loading = false;
            const oldHost = String(row.expected_host_id || '');
            const newHost = observedHostId(probe);
            if (!oldHost || !newHost) {
                render('Could not obtain both the pinned and currently observed host identities.', 'warn');
                return;
            }
            if (!confirm(`Trust the new host identity for “${row.name || row.id}”?\n\nOld: ${oldHost}\nNew: ${newHost}\n\nOnly continue if this server was intentionally replaced or reinstalled.`)) return;
            await act(() => apiClient.connectionRetrust(connectionId, {
                confirm: true,
                old_host_id: oldHost,
                new_host_id: newHost,
            }), 'New host identity trusted.', { connectionId, phase: 'retrust' });
        }
    }

    if (ws && typeof ws.on === 'function') {
        ws.on('connection_state', (event) => {
            const connectionId = String(event?.connection_id || '');
            if (!connectionId) return;
            mergePayload(event, connectionId);
            if (accessState === 'ready') render();
        });
    }
    window.addEventListener('ouro:settings-subtab-shown', (event) => {
        if (event.detail?.tab === 'connections') load();
    });
    render();
    if (root.dataset?.activeSettingsTab === 'connections') load();
}
