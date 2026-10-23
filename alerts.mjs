// Alert lifecycle: raise, escalate, resolve, acknowledge, group and deliver.
// The transport (notify) is injected, so the rules that decide who gets paged, and when, are tested without a network.
import { AsyncLocalStorage } from 'node:async_hooks';
import crypto from 'node:crypto';

export const RANK = { P1: 0, P2: 1, P3: 2 };
export const BURST = 3;                       // more messages than this in one run become a single summary
export const REPEAT_P1_MS = 10 * 60_000;      // unacknowledged P1s ring again
export const RETRY_MS = 10 * 60_000;          // P2s that never reached a channel are sent again
export const ONBOARD_GRACE_MS = 3600_000;     // findings of an onboarding that never got summarised

/**
 * notify(prio, title, body, key) → Promise<{ sent, failed, total }>
 * Every P1/P2 alert keeps `deliveredAt` until a channel confirmed it, so a crash or an outage never loses one silently.
 * onEvent(kind, alert) hears what a client may hear about: 'new', 'worse', 'resolved' (also quiet ones), 'after' (maintenance), never repeats or retries.
 */
export function createAlerts({ state, T, notify, applyAccept, now = () => Date.now(), save = () => {}, isMuted = () => false, onEvent = () => {} }) {
  state.alerts ||= {}; state.history ||= []; state.groups ||= {}; state.scanned ||= {};
  const queue = new AsyncLocalStorage();
  const onboarding = {}; // kind -> Set(assetId) while that kind's first scan runs
  const inOnboarding = (key, asset) => Object.entries(onboarding).some(([k, s]) => key.startsWith(`${k}:`) && s.has(asset));

  const histOf = a => { for (let i = state.history.length - 1; i >= 0; i--) { const h = state.history[i]; if (h.key === a.key && h.first === a.first) return h; } return null; };
  const histNote = (a, fields) => { const h = histOf(a); if (h) Object.assign(h, fields); };

  function markDelivered(keys) {
    const t = now();
    for (const k of keys) { const a = state.alerts[k]; if (a) { a.deliveredAt = t; delete a.onb; } }
  }

  async function deliver(m) {
    let r;
    try { r = await notify(m.prio, m.title, m.body, m.key); } catch { r = { sent: 0 }; }
    if (r?.sent) markDelivered(m.keys);
    return r;
  }

  // Inside a scheduled run, messages are collected and flushed together; anywhere else they go out at once
  function send(prio, title, body, key = null, keys = key && !key.startsWith('group:') ? [key] : []) {
    const m = { prio, title, body, key, keys };
    const q = queue.getStore();
    if (q) q.push(m); else deliver(m);
  }

  // A group key acknowledges every alert it summarises (so a burst can be acknowledged from the phone)
  function group(keys) {
    const id = crypto.randomBytes(6).toString('hex');
    state.groups[id] = { keys: [...new Set(keys)], at: now() };
    return `group:${id}`;
  }

  async function flush(name, q) {
    const real = q.filter(m => m.prio !== 'P3');
    if (real.length <= BURST) { for (const m of real) await deliver(m); return; }
    const sorted = [...real].sort((a, b) => RANK[a.prio] - RANK[b.prio]);
    const keys = [...new Set(sorted.flatMap(m => m.keys))];
    const body = sorted.slice(0, 8).map(m => `• ${m.prio} ${m.title}`).join('\n') + (real.length > 8 ? `\n${T.more}` : '');
    await deliver({ prio: sorted[0].prio, title: T.burst(real.length, name), body, key: keys.length ? group(keys) : null, keys });
  }

  // Run one scheduled check: its messages are flushed when it ends, grouped if there are many
  async function run(name, fn) {
    const q = [];
    try { return await queue.run(q, fn); }
    finally { await flush(name, q); }
  }

  function escalate(a, prio, title) {
    Object.assign(a, { prio, ack: false, sentAt: now(), deliveredAt: null });
    histNote(a, { prio });
    if (isMuted(a.asset)) a.muted = true; else { send(prio, title, a.body, a.key); onEvent('worse', a); }
  }

  // raise: create (deduplicated by key) or update an alert. A worse priority re-pages: the old acknowledgement no longer covers it.
  // `accept` makes it a change alert (acknowledging accepts the new value as baseline); `extra` stores fields such as a KEV term.
  function raise(key, prio, title, body, asset, accept, extra) {
    const t = now(), a = state.alerts[key];
    if (accept) body = `${body} ${T.acceptHint}`;
    if (!a) {
      const al = state.alerts[key] = { key, prio, title, body, asset, first: t, sentAt: t, ack: false, deliveredAt: null, ...(accept && { accept }), ...extra };
      state.history.push({ key, prio, title, asset, first: t });
      if (isMuted(asset)) al.muted = true;        // maintenance window: kept, sent when the window ends if still open
      else if (inOnboarding(key, asset)) al.onb = t; // summarised by onboard(), not paged one by one
      else { send(prio, title, body, key); onEvent('new', al); }
      return al;
    }
    Object.assign(a, { title, body }, accept && { accept }, extra);
    if (RANK[prio] < RANK[a.prio]) escalate(a, prio, T.escalated(title));
    return a;
  }

  function resolve(key, msg, { quiet = false } = {}) {
    const a = state.alerts[key];
    if (!a) return;
    delete state.alerts[key];
    histNote(a, { resolvedAt: now() });
    if (!quiet && !a.muted && a.prio !== 'P3') send('P2', T.recovered(a.title), msg || ''); // nothing to recover from if it was never sent
    if (!a.muted) onEvent('resolved', a); // even when quiet for you: a client who was told about it hears it is fixed
  }

  function ack(key) {
    if (String(key).startsWith('group:')) {
      const g = state.groups[key.slice(6)];
      if (!g) return false;
      for (const k of g.keys) ackOne(k);
      delete state.groups[key.slice(6)];
      save();
      return true;
    }
    const ok = ackOne(key);
    if (ok) save();
    return ok;
  }
  function ackOne(key) {
    const a = state.alerts[key];
    if (!a) return false;
    const t = now();
    histNote(a, { ackAt: a.ackAt || t, ...(a.accept && { resolvedAt: t, accepted: true }) });
    if (a.accept) { applyAccept(state, a.accept); delete state.alerts[key]; }
    else { a.ack = true; a.ackAt ||= t; }
    return true;
  }

  // First scan of a kind for new assets: findings are stored quietly and announced in one summary.
  // If the scan fails half-way, its findings keep their `onb` mark and join the next summary instead of staying silent.
  function onboard(inv, kind, fn) {
    const fresh = new Set(inv.filter(a => !state.scanned[`${kind}:${a.id}`]).map(a => a.id));
    onboarding[kind] = fresh;
    return Promise.resolve().then(fn).then(() => {
      delete onboarding[kind];
      if (!fresh.size) return;
      for (const id of fresh) state.scanned[`${kind}:${id}`] = now();
      summarize(kind, Object.values(state.alerts).filter(a => a.onb && !a.muted && fresh.has(a.asset) && a.key.startsWith(`${kind}:`)), inv);
    }, e => { delete onboarding[kind]; throw e; });
  }

  function summarize(kind, found, inv = []) {
    if (!found.length) return;
    const c = { P1: 0, P2: 0, P3: 0 };
    found.forEach(a => c[a.prio]++);
    const keys = found.map(a => a.key);
    if (!c.P1 && !c.P2) { markDelivered(keys); return; } // P3-only: the daily digest covers them
    const names = inv.filter(a => found.some(x => x.asset === a.id)).map(a => `${a.client}/${a.name}`).join(', ');
    send(c.P1 ? 'P1' : 'P2', T.onboard(kind, found.length), T.onboardBody(names || '—', c), group(keys), keys);
  }

  // Health loop: P1s ring again, undelivered P2s are retried, forgotten onboarding findings are summarised, old groups expire
  function sweep(t = now()) {
    const leftovers = [];
    for (const a of Object.values(state.alerts)) {
      if (a.muted) {
        if (isMuted(a.asset)) continue;
        delete a.muted; // the window is over and the problem is still there: now it is news
        if (!a.ack && a.prio !== 'P3') { a.sentAt = t; send(a.prio, T.afterMaintenance(a.title), a.body, a.key); onEvent('after', a); }
        continue;
      }
      if (a.ack || a.prio === 'P3') continue;
      if (a.onb) {
        if (a.prio === 'P1' && t - a.onb > REPEAT_P1_MS) delete a.onb; // a P1 never waits long for a summary
        else { if (t - a.onb > ONBOARD_GRACE_MS) leftovers.push(a); continue; }
      }
      if (a.prio === 'P1' && t - a.sentAt > REPEAT_P1_MS) { a.sentAt = t; send('P1', T.repeat(a.title), a.body, a.key); }
      else if (a.prio === 'P2' && !a.deliveredAt && t - (a.retryAt || a.first) > RETRY_MS) { a.retryAt = t; send('P2', a.title, a.body, a.key); }
    }
    if (leftovers.length) summarize('pending', leftovers);
    for (const [id, g] of Object.entries(state.groups)) if (t - g.at > 14 * 864e5) delete state.groups[id];
  }

  // The instant an acknowledge link is bound to: the alert's or the group's creation time
  const firstOf = key => (String(key).startsWith('group:') ? state.groups[key.slice(6)]?.at : state.alerts[key]?.first) ?? null;

  return { raise, resolve, ack, send, run, onboard, sweep, escalate, histNote, group, firstOf, markDelivered };
}
