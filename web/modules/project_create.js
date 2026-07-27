// New Project dialog + project row actions (v6.59.0, Phase 3).
//
// One modal, five sources: file-less | genesis (fresh managed
// folder) | attach an existing folder (server-side directory browser — works in
// web/Docker where no native picker exists; optional init_git attach-snapshot)
// | clone a git URL (server-side, typed auth_required). The dialog carries the
// honest trust line: attaching gives the agent write+shell in that folder
// (notification model — attaching IS the grant; no second confirmation).
import { openConfirmDialog } from './confirm_dialog.js';
import { isSelectableRemoteConnection } from './connections_ui.js';

// Mirrored from the frozen backend PROJECT_NAME_MAX contract.
const PROJECT_NAME_MAX = 80;

export function makeSshWorkspaceRef(connectionId, remoteRoot) {
    const cleanConnectionId = String(connectionId || '').trim();
    const cleanRemoteRoot = String(remoteRoot || '').trim();
    if (!cleanConnectionId || !cleanRemoteRoot) return null;
    return {
        kind: 'ssh',
        connection_id: cleanConnectionId,
        remote_root: cleanRemoteRoot,
    };
}

export function openNewProjectDialog({ apiClient, onCreated }) {
    const maxNameLength = PROJECT_NAME_MAX;
    return new Promise((resolve) => {
        const backdrop = document.createElement('div');
        backdrop.className = 'marketplace-modal-backdrop new-project-backdrop';
        backdrop.innerHTML = `
            <div class="marketplace-modal new-project-dialog" role="dialog" aria-modal="true" aria-labelledby="new-project-title">
                <div class="marketplace-modal-head">
                    <h3 id="new-project-title">New Project</h3>
                    <button type="button" class="btn btn-default btn-sm" data-np-cancel aria-label="Close">Close</button>
                </div>
                <div class="marketplace-modal-body">
                    <label class="new-project-field">
                        <span>Name</span>
                        <input class="files-modal-input" data-np-name type="text" placeholder="My project" maxlength="${maxNameLength}">
                    </label>
                    <fieldset class="new-project-sources">
                        <legend>Working folder</legend>
                        <label><input type="radio" name="np-source" value="fileless" checked> None — chat/research project (no folder)</label>
                        <label><input type="radio" name="np-source" value="genesis"> New managed folder (fresh git repo under the projects root)</label>
                        <label><input type="radio" name="np-source" value="attach"> Attach an existing folder…</label>
                        <label><input type="radio" name="np-source" value="clone"> Clone a git URL…</label>
                        <label><input type="radio" name="np-source" value="ssh"> Use a folder over SSH…</label>
                    </fieldset>
                    <div class="new-project-source-detail" data-np-attach hidden>
                        <div class="new-project-browser">
                            <div class="new-project-browser-path" data-np-path></div>
                            <div class="new-project-browser-list" data-np-dirs></div>
                        </div>
                        <label class="local-toggle" title="Runs git init + an 'attach snapshot' commit of the current state with a local identity. Never done without this checkbox.">
                            <input type="checkbox" data-np-initgit>
                            Initialize git here if missing (attach-snapshot commit)
                        </label>
                    </div>
                    <div class="new-project-source-detail" data-np-clone hidden>
                        <label class="new-project-field">
                            <span>Git URL</span>
                            <input class="files-modal-input" data-np-giturl type="text" placeholder="https://github.com/user/repo.git or git@github.com:user/repo.git">
                        </label>
                    </div>
                    <div class="new-project-source-detail" data-np-ssh hidden>
                        <label class="new-project-field">
                            <span>SSH connection</span>
                            <select class="files-modal-input" data-np-connection></select>
                        </label>
                        <div class="new-project-browser">
                            <div class="new-project-browser-path" data-np-remote-path></div>
                            <div class="new-project-browser-list" data-np-remote-dirs aria-live="polite"></div>
                        </div>
                    </div>
                    <p class="new-project-trust-note" data-np-trust hidden>
                        The agent gets <strong>read, write and shell</strong> in this folder when working on this project's tasks.
                    </p>
                    <p class="new-project-error" data-np-error role="alert" hidden></p>
                </div>
                <div class="marketplace-modal-actions">
                    <button type="button" class="btn btn-default" data-np-cancel>Cancel</button>
                    <button type="button" class="btn btn-primary" data-np-create>Create project</button>
                </div>
            </div>
        `;
        const q = (sel) => backdrop.querySelector(sel);
        let selectedDir = '';
        let browsePath = '';
        let selectedRemoteDir = '';
        let remoteBrowseRevision = 0;
        let connectionLoadRevision = 0;

        const setError = (text) => {
            const el = q('[data-np-error]');
            el.textContent = text || '';
            el.hidden = !text;
        };

        async function renderDirs(path) {
            const listEl = q('[data-np-dirs]');
            const pathEl = q('[data-np-path]');
            listEl.textContent = 'Loading…';
            try {
                const data = await apiClient.fsDirs(path);
                browsePath = data.path;
                pathEl.textContent = '';
                const cur = document.createElement('strong');
                cur.textContent = data.path;
                pathEl.appendChild(cur);
                const select = document.createElement('button');
                select.type = 'button';
                select.className = 'btn btn-sm ' + (selectedDir === data.path ? 'btn-primary' : 'btn-default');
                select.textContent = selectedDir === data.path ? 'Selected ✓' : 'Select this folder';
                select.addEventListener('click', () => {
                    selectedDir = data.path;
                    q('[data-np-trust]').hidden = false;
                    renderDirs(data.path);
                });
                pathEl.appendChild(select);
                listEl.textContent = '';
                if (data.parent) {
                    const up = document.createElement('button');
                    up.type = 'button';
                    up.className = 'new-project-dir-row new-project-dir-up';
                    up.textContent = '.. (up)';
                    up.addEventListener('click', () => renderDirs(data.parent));
                    listEl.appendChild(up);
                }
                for (const dir of data.dirs || []) {
                    const row = document.createElement('button');
                    row.type = 'button';
                    row.className = 'new-project-dir-row';
                    row.textContent = `${dir.name}${dir.is_git ? '  ⎇' : ''}`;
                    row.title = dir.path + (dir.is_git ? ' (git repository)' : '');
                    row.addEventListener('click', () => renderDirs(dir.path));
                    listEl.appendChild(row);
                }
                if (!(data.dirs || []).length) {
                    const empty = document.createElement('div');
                    empty.className = 'new-project-dir-empty';
                    empty.textContent = '(no subfolders)';
                    listEl.appendChild(empty);
                }
                if (data.truncated) {
                    const more = document.createElement('div');
                    more.className = 'new-project-dir-empty';
                    more.textContent = '(more folders exist — showing the first 500)';
                    listEl.appendChild(more);
                }
            } catch (e) {
                listEl.textContent = `Cannot browse: ${e?.message || e}`;
            }
        }

        async function renderRemoteDirs(path = '', knownGitRoot = null) {
            const connectionId = q('[data-np-connection]')?.value || '';
            const listEl = q('[data-np-remote-dirs]');
            const pathEl = q('[data-np-remote-path]');
            if (!connectionId) {
                listEl.textContent = 'Choose an active SSH connection.';
                pathEl.textContent = '';
                return;
            }
            const revision = ++remoteBrowseRevision;
            listEl.textContent = 'Loading…';
            try {
                const data = await apiClient.connectionDirs(connectionId, path);
                if (
                    revision !== remoteBrowseRevision
                    || q('[data-np-connection]')?.value !== connectionId
                ) return;
                pathEl.textContent = '';
                const cur = document.createElement('strong');
                cur.textContent = data.path;
                pathEl.appendChild(cur);
                const gitStatus = document.createElement('span');
                gitStatus.className = 'new-project-dir-status';
                gitStatus.textContent = knownGitRoot === true
                    ? 'Git worktree root ✓'
                    : knownGitRoot === false
                        ? 'Not a Git worktree root'
                        : 'Git root will be validated before creation';
                pathEl.appendChild(gitStatus);
                const select = document.createElement('button');
                select.type = 'button';
                select.className = 'btn btn-sm ' + (selectedRemoteDir === data.path ? 'btn-primary' : 'btn-default');
                select.textContent = selectedRemoteDir === data.path ? 'Selected ✓' : 'Select and validate';
                select.disabled = knownGitRoot === false;
                select.addEventListener('click', () => {
                    selectedRemoteDir = data.path;
                    q('[data-np-trust]').hidden = false;
                    renderRemoteDirs(data.path, knownGitRoot);
                });
                pathEl.appendChild(select);
                listEl.textContent = '';
                if (data.parent) {
                    const up = document.createElement('button');
                    up.type = 'button';
                    up.className = 'new-project-dir-row new-project-dir-up';
                    up.textContent = '.. (up)';
                    up.addEventListener('click', () => renderRemoteDirs(data.parent));
                    listEl.appendChild(up);
                }
                for (const dir of data.dirs || []) {
                    const row = document.createElement('button');
                    row.type = 'button';
                    row.className = 'new-project-dir-row';
                    row.textContent = `${dir.name}${dir.is_git ? '  ⎇' : ''}`;
                    row.title = dir.path + (dir.is_git ? ' (git repository)' : '');
                    row.addEventListener('click', () => renderRemoteDirs(dir.path, Boolean(dir.is_git)));
                    listEl.appendChild(row);
                }
                if (!(data.dirs || []).length) {
                    const empty = document.createElement('div');
                    empty.className = 'new-project-dir-empty';
                    empty.textContent = '(no subfolders)';
                    listEl.appendChild(empty);
                }
                if (data.truncated) {
                    const more = document.createElement('div');
                    more.className = 'new-project-dir-empty';
                    more.textContent = '(more folders exist — showing the bounded result)';
                    listEl.appendChild(more);
                }
            } catch (e) {
                if (revision !== remoteBrowseRevision) return;
                listEl.textContent = `Cannot browse remote folders: ${e?.body?.error || e?.message || e}`;
            }
        }

        async function loadConnections() {
            const select = q('[data-np-connection]');
            const revision = ++connectionLoadRevision;
            select.innerHTML = '<option value="">Loading connections…</option>';
            try {
                const data = await apiClient.connections();
                if (revision !== connectionLoadRevision) return;
                const active = (data.connections || []).filter(isSelectableRemoteConnection);
                select.textContent = '';
                const empty = document.createElement('option');
                empty.value = '';
                empty.textContent = active.length
                    ? 'Choose a bootstrapped healthy connection'
                    : 'No fresh bootstrapped connections — run Bootstrap (or Test to refresh health) in Settings → Connections';
                select.appendChild(empty);
                active.forEach((row) => {
                    const option = document.createElement('option');
                    option.value = row.id;
                    option.textContent = `${row.name} (${row.ssh_alias})`;
                    select.appendChild(option);
                });
            } catch (e) {
                if (revision !== connectionLoadRevision) return;
                select.innerHTML = '<option value="">Connections unavailable</option>';
                const code = e?.body?.error_code || '';
                setError(code === 'owner_auth_required'
                    ? 'Unlock owner access in Settings → Connections, then reopen this dialog.'
                    : code === 'owner_auth_not_configured'
                        ? 'Configure a Network Password and restart Ouroboros before using SSH Projects.'
                        : (e?.body?.error || e?.message || String(e)));
            }
        }

        function syncSource() {
            const source = backdrop.querySelector('input[name="np-source"]:checked')?.value || 'fileless';
            q('[data-np-attach]').hidden = source !== 'attach';
            q('[data-np-clone]').hidden = source !== 'clone';
            q('[data-np-ssh]').hidden = source !== 'ssh';
            q('[data-np-trust]').hidden = !(
                (source === 'attach' && selectedDir)
                || (source === 'ssh' && selectedRemoteDir)
                || source === 'clone'
                || source === 'genesis'
            );
            if (source === 'attach' && !browsePath) renderDirs('');
            if (source === 'ssh' && !q('[data-np-connection]').options.length) loadConnections();
        }
        backdrop.querySelectorAll('input[name="np-source"]').forEach((radio) => {
            radio.addEventListener('change', syncSource);
        });
        q('[data-np-connection]').addEventListener('change', () => {
            selectedRemoteDir = '';
            remoteBrowseRevision += 1;
            renderRemoteDirs('');
        });

        let settled = false;
        const finish = (value) => {
            if (settled) return;
            settled = true;
            remoteBrowseRevision += 1;
            connectionLoadRevision += 1;
            document.removeEventListener('keydown', onKey);
            backdrop.remove();
            resolve(value);
        };
        const onKey = (event) => {
            if (event.key === 'Escape') finish(null);
        };
        document.addEventListener('keydown', onKey);

        async function create() {
            setError('');
            const name = (q('[data-np-name]').value || '').trim();
            const source = backdrop.querySelector('input[name="np-source"]:checked')?.value || 'fileless';
            if (!name) { setError('Give the project a name.'); return; }
            const payload = { name };
            if (source === 'genesis') payload.with_workspace = true;
            if (source === 'attach') {
                if (!selectedDir) { setError('Pick a folder to attach (Select this folder).'); return; }
                payload.path = selectedDir;
                payload.init_git = Boolean(q('[data-np-initgit]').checked);
            }
            if (source === 'clone') {
                const url = (q('[data-np-giturl]').value || '').trim();
                if (!url) { setError('Enter the git URL to clone.'); return; }
                payload.git_url = url;
            }
            if (source === 'ssh') {
                const connectionId = q('[data-np-connection]').value || '';
                if (!connectionId) { setError('Choose an SSH connection.'); return; }
                if (!selectedRemoteDir) { setError('Pick a remote folder (Select this folder).'); return; }
                payload.workspace_ref = makeSshWorkspaceRef(connectionId, selectedRemoteDir);
            }
            const btn = q('[data-np-create]');
            btn.disabled = true;
            btn.textContent = source === 'clone' ? 'Cloning…' : (source === 'ssh' ? 'Connecting…' : 'Creating…');
            try {
                const data = await apiClient.projectCreate(payload);
                if (data?.error) throw new Error(data.error);
                finish(data?.project || null);
                onCreated?.(data?.project || null);
            } catch (e) {
                const detail = e?.body?.error || e?.message || String(e);
                const code = e?.body?.error_code || '';
                const action = e?.body?.action ? ` Next: ${e.body.action}.` : '';
                setError(code === 'auth_required'
                    ? `This repository needs credentials (private repo). Set up git access on this machine, then retry. Detail: ${detail}`
                    : ['workspace_not_git', 'workspace_not_git_root', 'workspace_root_mismatch'].includes(code)
                        ? `The selected remote folder is not the canonical Git worktree root. Choose the folder marked ⎇ and retry.${action}`
                        : `${detail}${action}`);
                btn.disabled = false;
                btn.textContent = 'Create project';
            }
        }
        backdrop.addEventListener('click', (event) => {
            if (event.target === backdrop || event.target.closest('[data-np-cancel]')) finish(null);
            else if (event.target.closest('[data-np-create]')) create();
        });
        document.body.appendChild(backdrop);
        q('[data-np-name]').focus();
    });
}

let closeOpenProjectRowMenu = null;

// Accessible row menu: Rename/Delete only. `project` is a sidebar read model;
// callbacks refresh the authoritative registry projection.
export async function openProjectRowMenu(project, { apiClient, anchorEl, onChanged }) {
    const maxNameLength = PROJECT_NAME_MAX;
    closeOpenProjectRowMenu?.();
    const menu = document.createElement('div');
    menu.className = 'project-row-menu';
    menu.setAttribute('role', 'menu');
    menu.setAttribute('aria-label', `Actions for ${project.name || project.id}`);
    menu.innerHTML = `
        <button type="button" role="menuitem" data-prm="rename">Rename…</button>
        <button type="button" role="menuitem" class="danger" data-prm="delete">Delete project…</button>
    `;
    const rect = anchorEl.getBoundingClientRect();
    const close = ({ restoreFocus = false } = {}) => {
        menu.remove();
        document.removeEventListener('click', onDoc, true);
        document.removeEventListener('keydown', onKey, true);
        if (closeOpenProjectRowMenu === close) closeOpenProjectRowMenu = null;
        if (restoreFocus && anchorEl.isConnected) anchorEl.focus();
    };
    const onDoc = (event) => { if (!menu.contains(event.target)) close(); };
    const onKey = (event) => {
        const items = Array.from(menu.querySelectorAll('[role="menuitem"]'));
        const index = items.indexOf(document.activeElement);
        if (event.key === 'Escape') {
            event.preventDefault();
            close({ restoreFocus: true });
        } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            const delta = event.key === 'ArrowDown' ? 1 : -1;
            items[(index + delta + items.length) % items.length]?.focus();
        } else if (event.key === 'Home' || event.key === 'End') {
            event.preventDefault();
            items[event.key === 'Home' ? 0 : items.length - 1]?.focus();
        }
    };
    closeOpenProjectRowMenu = close;
    document.addEventListener('click', onDoc, true);
    document.addEventListener('keydown', onKey, true);
    menu.addEventListener('click', async (event) => {
        const action = event.target.closest('[data-prm]')?.dataset?.prm;
        if (!action) return;
        close();
        if (action === 'rename') {
            const res = await openConfirmDialog({
                title: 'Rename project',
                body: `New name for “${project.name || project.id}”:`,
                input: true,
                initialValue: project.name || project.id,
                confirmLabel: 'Rename',
            });
            const newName = res?.confirmed ? String(res.value || '').trim() : '';
            if (newName.length > maxNameLength) {
                alert(`Project names are limited to ${maxNameLength} characters.`);
            } else if (newName && newName !== project.name) {
                try { await apiClient.projectUpdate(project.id, newName); onChanged?.(); }
                catch (e) { alert(`Rename failed: ${e?.body?.error || e?.message || e}`); }
            }
            if (anchorEl.isConnected) anchorEl.focus();
        } else if (action === 'delete') {
            const ok = await openConfirmDialog({
                title: 'Delete project',
                body: `Delete “${project.name || project.id}”? Running work will be cancelled. The Project will be removed from the active UI; its id, chat history, task bindings, memory, and working folder are preserved.`,
                confirmLabel: 'Delete',
                danger: true,
            });
            if (ok === true) {
                onChanged?.({ projectId: project.id, lifecycle: 'deleting', optimistic: true });
                try { await apiClient.projectDelete(project.id); }
                catch (e) { alert(`Delete did not finish: ${e?.body?.error || e?.message || e}`); }
                finally { onChanged?.({ authoritative: true }); }
            }
            if (anchorEl.isConnected) anchorEl.focus();
        }
    });
    document.body.appendChild(menu);
    const menuRect = menu.getBoundingClientRect();
    const margin = 8;
    const top = Math.min(
        Math.max(margin, rect.bottom + 4),
        Math.max(margin, window.innerHeight - menuRect.height - margin),
    );
    const left = Math.min(
        Math.max(margin, rect.right - menuRect.width),
        Math.max(margin, window.innerWidth - menuRect.width - margin),
    );
    menu.style.setProperty('--prm-top', `${Math.round(top)}px`);
    menu.style.setProperty('--prm-left', `${Math.round(left)}px`);
    menu.querySelector('[role="menuitem"]')?.focus();
}
