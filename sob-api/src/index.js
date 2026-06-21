// Stack OverBoard API — Cloudflare Worker
// Secrets set via: wrangler secret put SOB_API_KEY / FIREBASE_SERVICE_ACCOUNT

const VALID_STATUSES = ['Pending', 'In Progress', 'DONE'];
const VALID_PRIORITIES = ['High', 'Medium', 'Low'];

// ── JWT / Firestore auth ──────────────────────────────────────────────────────

async function getFirestoreToken(env) {
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const now = Math.floor(Date.now() / 1000);

  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: sa.client_email,
    sub: sa.client_email,
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
    scope: 'https://www.googleapis.com/auth/datastore',
  };

  const b64 = obj => btoa(JSON.stringify(obj)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const sigInput = `${b64(header)}.${b64(payload)}`;

  // Import the RSA private key
  const pemBody = sa.private_key.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  const keyDer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    'pkcs8', keyDer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['sign']
  );

  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(sigInput));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

  const jwt = `${sigInput}.${sigB64}`;

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  });
  const { access_token } = await tokenRes.json();
  return access_token;
}

// ── Firestore helpers ─────────────────────────────────────────────────────────

function toFirestoreValue(val) {
  if (val === null || val === undefined) return { nullValue: null };
  if (typeof val === 'string') return { stringValue: val };
  if (typeof val === 'number') return { integerValue: String(val) };
  if (typeof val === 'boolean') return { booleanValue: val };
  if (typeof val === 'object') {
    const fields = {};
    for (const [k, v] of Object.entries(val)) fields[k] = toFirestoreValue(v);
    return { mapValue: { fields } };
  }
  return { stringValue: String(val) };
}

function toFirestoreDoc(obj) {
  const fields = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) fields[k] = toFirestoreValue(v);
  }
  return { fields };
}

function fromFirestoreDoc(doc) {
  function parseVal(v) {
    if (v.stringValue !== undefined) return v.stringValue;
    if (v.integerValue !== undefined) return Number(v.integerValue);
    if (v.doubleValue !== undefined) return v.doubleValue;
    if (v.booleanValue !== undefined) return v.booleanValue;
    if (v.nullValue !== undefined) return null;
    if (v.timestampValue !== undefined) return v.timestampValue;
    if (v.mapValue) {
      const out = {};
      for (const [k, fv] of Object.entries(v.mapValue.fields || {})) out[k] = parseVal(fv);
      return out;
    }
    if (v.arrayValue) return (v.arrayValue.values || []).map(parseVal);
    return null;
  }
  const out = {};
  for (const [k, v] of Object.entries(doc.fields || {})) out[k] = parseVal(v);
  return out;
}

async function firestorePost(projectId, collection, doc, token) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(doc),
  });
  return res.json();
}

async function firestorePatch(projectId, collection, docId, fields, token) {
  const updateMask = Object.keys(fields).map(f => `updateMask.fieldPaths=${encodeURIComponent(f)}`).join('&');
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}/${docId}?${updateMask}`;
  const res = await fetch(url, {
    method: 'PATCH',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, toFirestoreValue(v)])) }),
  });
  return res.json();
}

async function getNextTicketId(projectId, boardPrefix, token) {
  const counterDocUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/meta/counters`;
  const res = await fetch(counterDocUrl, { headers: { 'Authorization': `Bearer ${token}` } });
  const json = await res.json();
  const current = json.fields?.[boardPrefix]?.integerValue ? Number(json.fields[boardPrefix].integerValue) : 0;
  const next = current + 1;
  // Write back
  await fetch(counterDocUrl, {
    method: 'PATCH',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: { [boardPrefix]: toFirestoreValue(next) } }),
  });
  return next;
}

function formatTicketId(prefix, num) {
  return `${prefix.toUpperCase()}-${String(num).padStart(3, '0')}`;
}

function getBoardPrefix(boardId, boardName) {
  if (boardId === 'hirush') return 'HIR';
  // split on spaces AND camelCase boundaries (e.g. "OverBoard" → ["Over","Board"])
  const name = (boardName || boardId).replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[^a-zA-Z0-9\s]/g, ' ').trim();
  const words = name.split(/\s+/);
  const prefix = words.length === 1
    ? words[0].slice(0, 3).toUpperCase()
    : words.map(w => w[0] || '').join('').toUpperCase().slice(0, 6) || 'TKT';
  return /^[0-9]/.test(prefix) ? 'B' + prefix.slice(0, 5) : prefix;
}

async function firestoreQuery(projectId, collection, filters, orderBy, limit, token) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents:runQuery`;
  const structuredQuery = {
    from: [{ collectionId: collection }],
    where: filters.length === 1 ? filters[0] : {
      compositeFilter: { op: 'AND', filters }
    },
    orderBy: orderBy ? [{ field: { fieldPath: orderBy.field }, direction: orderBy.direction || 'ASCENDING' }] : undefined,
    limit: limit || 100,
  };
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ structuredQuery }),
  });
  return res.json();
}

function makeFieldFilter(field, op, value) {
  return {
    fieldFilter: {
      field: { fieldPath: field },
      op,
      value: toFirestoreValue(value),
    }
  };
}

// ── Router ────────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    // Auth check
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!token || token !== env.SOB_API_KEY) {
      return Response.json({ error: 'Invalid or missing API key.' }, { status: 401, headers: cors });
    }

    const path = url.pathname.replace(/\/$/, '');
    const projectId = env.FIREBASE_PROJECT_ID;

    try {
      // POST /tickets — create a ticket
      if (request.method === 'POST' && path === '/tickets') {
        const body = await request.json().catch(() => ({}));
        const {
          title, desc = '', module: mod = 'Other', priority = 'Medium',
          type = 'Feature', role = 'Shared (Global)', status = 'Pending',
          boardId = 'hirush', dueDate, assignee, createdBy,
        } = body;

        if (!title?.trim()) return Response.json({ error: '`title` is required.' }, { status: 400, headers: cors });
        if (!VALID_STATUSES.includes(status)) return Response.json({ error: `status must be one of: ${VALID_STATUSES.join(', ')}` }, { status: 400, headers: cors });
        if (!VALID_PRIORITIES.includes(priority)) return Response.json({ error: `priority must be one of: ${VALID_PRIORITIES.join(', ')}` }, { status: 400, headers: cors });

        const fsToken = await getFirestoreToken(env);

        // Get max order
        const existing = await firestoreQuery(projectId, 'tasks',
          [makeFieldFilter('boardId', 'EQUAL', boardId)],
          { field: 'order', direction: 'DESCENDING' }, 1, fsToken
        );
        const maxOrder = existing[0]?.document
          ? (Number(existing[0].document.fields?.order?.integerValue ?? 0) + 1) : 0;

        const now = new Date().toISOString();
        const task = {
          title: title.trim(), desc: desc.trim(), module: mod,
          priority, type, role, status, boardId, order: maxOrder,
          createdAt: now, lastEditedAt: now,
          createdBy: createdBy || { name: 'API', email: 'api@stackoverboard' },
          lastEditedBy: createdBy || { name: 'API', email: 'api@stackoverboard' },
        };
        if (dueDate) task.dueDate = dueDate;
        if (assignee) task.assignee = assignee;

        // Auto-assign ticketId — look up board name for correct prefix
        let boardName = boardId;
        if (boardId !== 'hirush') {
          const boardDoc = await fetch(`https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/boards/${boardId}`, { headers: { 'Authorization': `Bearer ${fsToken}` } });
          const boardJson = await boardDoc.json();
          boardName = boardJson.fields?.name?.stringValue || boardId;
        }
        const boardPrefix = getBoardPrefix(boardId, boardName);
        const ticketNum = await getNextTicketId(projectId, boardPrefix, fsToken);
        task.ticketId = formatTicketId(boardPrefix, ticketNum);

        const result = await firestorePost(projectId, 'tasks', toFirestoreDoc(task), fsToken);
        const id = result.name?.split('/').pop();

        return Response.json({ id, message: 'Ticket created.', ticket: { id, ...task } }, { status: 201, headers: cors });
      }

      // GET /boards — list all boards
      if (request.method === 'GET' && path === '/boards') {
        const fsToken = await getFirestoreToken(env);
        const url2 = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/boards`;
        const res = await fetch(url2, { headers: { 'Authorization': `Bearer ${fsToken}` } });
        const json = await res.json();
        const boards = (json.documents || []).map(doc => ({
          id: doc.name.split('/').pop(),
          name: doc.fields?.name?.stringValue || '',
          createdAt: doc.fields?.createdAt?.timestampValue || null,
        }));
        // always include hirush even if not in Firestore
        if (!boards.find(b => b.id === 'hirush')) boards.unshift({ id: 'hirush', name: 'Hirush' });
        return Response.json({ count: boards.length, boards }, { headers: cors });
      }

      // GET /tickets — list tickets
      if (request.method === 'GET' && path === '/tickets') {
        const boardId = url.searchParams.get('boardId') || 'hirush';
        const status = url.searchParams.get('status');

        const fsToken = await getFirestoreToken(env);

        // Fetch tasks matching boardId exactly
        const filters1 = [makeFieldFilter('boardId', 'EQUAL', boardId)];
        if (status) filters1.push(makeFieldFilter('status', 'EQUAL', status));
        const rows1 = await firestoreQuery(projectId, 'tasks', filters1, null, 500, fsToken);

        // For hirush board: also fetch old tasks with no boardId field (legacy seed data)
        let rows2 = [];
        if (boardId === 'hirush') {
          const filters2 = [makeFieldFilter('boardId', 'NOT_EQUAL', boardId)];
          // We fetch all then client-filter for missing boardId below
          const allRows = await firestoreQuery(projectId, 'tasks', [makeFieldFilter('order', 'GREATER_THAN_OR_EQUAL', -1)], null, 500, fsToken);
          rows2 = (allRows || []).filter(r => {
            if (!r.document) return false;
            const data = fromFirestoreDoc(r.document);
            return !data.boardId && !data.parentId;
          });
          if (status) rows2 = rows2.filter(r => fromFirestoreDoc(r.document).status === status);
        }

        const seen = new Set();
        const tickets = [...(rows1 || []), ...rows2]
          .filter(r => r.document)
          .map(r => ({ id: r.document.name.split('/').pop(), ...fromFirestoreDoc(r.document) }))
          .filter(t => { if (seen.has(t.id)) return false; seen.add(t.id); return true; })
          .filter(t => !t.parentId)
          .sort((a, b) => (a.order ?? 0) - (b.order ?? 0));

        return Response.json({ boardId, count: tickets.length, tickets }, { headers: cors });
      }

      // GET /tickets/:id — single ticket
      const ticketMatch = path.match(/^\/tickets\/([^/]+)$/);
      if (request.method === 'GET' && ticketMatch) {
        const id = ticketMatch[1];
        const fsToken = await getFirestoreToken(env);
        const res = await fetch(`https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/tasks/${id}`, {
          headers: { 'Authorization': `Bearer ${fsToken}` },
        });
        if (!res.ok) return Response.json({ error: 'Ticket not found.' }, { status: 404, headers: cors });
        const doc = await res.json();
        return Response.json({ id, ...fromFirestoreDoc(doc) }, { headers: cors });
      }

      // PATCH /tickets/:id — update ticket
      if (request.method === 'PATCH' && ticketMatch) {
        const id = ticketMatch[1];
        const body = await request.json().catch(() => ({}));
        const allowed = ['title','desc','module','priority','type','role','status','dueDate','assignee','boardId'];
        const fields = Object.fromEntries(Object.entries(body).filter(([k]) => allowed.includes(k)));
        if (!Object.keys(fields).length) return Response.json({ error: 'No valid fields to update.' }, { status: 400, headers: cors });
        fields.lastEditedAt = new Date().toISOString();
        const fsToken = await getFirestoreToken(env);
        await firestorePatch(projectId, 'tasks', id, fields, fsToken);
        return Response.json({ id, message: 'Ticket updated.', updated: fields }, { headers: cors });
      }

      // POST /admin/backfill-ids — assigns board-prefixed IDs to all parent tickets across all boards
      if (request.method === 'POST' && path === '/admin/backfill-ids') {
        const fsToken = await getFirestoreToken(env);

        // List ALL task documents
        const listUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/tasks?pageSize=500`;
        const listRes = await fetch(listUrl, { headers: { 'Authorization': `Bearer ${fsToken}` } });
        const listJson = await listRes.json();
        const allDocs = listJson.documents || [];

        const seenDocs = new Set();
        const allTickets = allDocs
          .filter(doc => { if (seenDocs.has(doc.name)) return false; seenDocs.add(doc.name); return true; })
          .map(doc => ({ id: doc.name.split('/').pop(), docName: doc.name, ...fromFirestoreDoc(doc) }))
          .filter(t => !t.parentId);

        // Fetch board names for correct prefix derivation
        const boardsRes = await fetch(`https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/boards`, { headers: { 'Authorization': `Bearer ${fsToken}` } });
        const boardsJson = await boardsRes.json();
        const boardNames = {};
        for (const doc of (boardsJson.documents || [])) {
          boardNames[doc.name.split('/').pop()] = doc.fields?.name?.stringValue || '';
        }

        // Group by boardId (no boardId = legacy hirush)
        const groups = {};
        for (const t of allTickets) {
          const bid = t.boardId || 'hirush';
          if (!groups[bid]) groups[bid] = [];
          groups[bid].push(t);
        }

        // Sort each group by order and assign sequential IDs
        const writes = [];
        const results = {};
        const counterFields = {};

        for (const [bid, tickets] of Object.entries(groups)) {
          const prefix = getBoardPrefix(bid, boardNames[bid] || '');
          tickets.sort((a, b) => (a.order ?? 9999) - (b.order ?? 9999));
          results[bid] = [];
          let counter = 0;
          for (const t of tickets) {
            counter++;
            const ticketId = formatTicketId(prefix, counter);
            results[bid].push({ id: t.id, ticketId });
            writes.push({
              update: { name: t.docName, fields: { ticketId: toFirestoreValue(ticketId) } },
              updateMask: { fieldPaths: ['ticketId'] },
            });
          }
          counterFields[prefix] = toFirestoreValue(counter);
        }

        // Update all counters in the same batch
        writes.push({
          update: {
            name: `projects/${projectId}/databases/(default)/documents/meta/counters`,
            fields: counterFields,
          },
          updateMask: { fieldPaths: Object.keys(counterFields) },
        });

        const batchUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents:batchWrite`;
        const batchRes = await fetch(batchUrl, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${fsToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ writes }),
        });
        const batchJson = await batchRes.json();
        if (batchJson.error) return Response.json({ error: batchJson.error }, { status: 500, headers: cors });

        const total = Object.values(results).reduce((s, r) => s + r.length, 0);
        return Response.json({ message: `Backfilled ${total} tickets across ${Object.keys(results).length} board(s).`, boards: results }, { headers: cors });
      }

      return Response.json({ error: 'Not found.', routes: ['GET /boards', 'GET /tickets', 'GET /tickets/:id', 'POST /tickets', 'PATCH /tickets/:id', 'POST /admin/backfill-ids'] }, { status: 404, headers: cors });

    } catch (err) {
      return Response.json({ error: err.message }, { status: 500, headers: cors });
    }
  }
};
