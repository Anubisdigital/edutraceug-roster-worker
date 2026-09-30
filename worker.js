/* ==================================================================
 * edutraceug-roster-worker — Cloudflare Worker
 * Single-file build.
 *
 * Accepts a school's student or teacher roster (xlsx/xls/xlsm/xltx/xltm/csv),
 * virus-scans it via Cloudmersive, archives the raw file to Cloudinary,
 * parses it with SheetJS, and merges structured rows into Firestore at
 * schools/{schoolId}/roster.
 *
 * All Firebase / Cloudinary / HTTP-server concerns are implemented against
 * REST APIs using `crypto.subtle` and `fetch`, not Node SDKs.
 * ================================================================== */

import * as XLSX from 'xlsx';

// ==================================================================
// Constants
// ==================================================================

const MAX_ROWS_PER_CALL = 1000;
const DEFAULT_MAX_FILE_SIZE_MB = 25;
const ACCEPTED_EXTENSIONS = ['.xlsx', '.xls', '.xlsm', '.xltx', '.xltm', '.csv'];

const ACCEPTED_MIME = new Set([
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-excel',
  'application/vnd.ms-excel.sheet.macroenabled.12',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.template',
  'application/vnd.ms-excel.template.macroenabled.12',
  'text/csv',
  'application/csv',
  'text/comma-separated-values',
  'text/plain',
  'application/octet-stream',
  '',
]);

const GOOGLE_JWKS_URL =
  'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const OAUTH_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const FIRESTORE_SCOPE = 'https://www.googleapis.com/auth/datastore';

const CLOUDMERSIVE_SCAN_URL = 'https://api.cloudmersive.com/virus/scan/file';
const SCAN_TIMEOUT_MS = 60_000;

const JWKS_TTL_MS = 6 * 60 * 60 * 1000;   // 6h
const OAUTH_SAFETY_SECONDS = 120;         // refresh 2 min before expiry

const RECORD_TYPES = new Set(['student', 'teacher']);

// Fields that participate in exact-match diffing.
const DATA_FIELDS = [
  'recordType',
  'firstName',
  'lastName',
  'class',
  'gender',
  'stream',
  'extraDetail',
];

// ==================================================================
// Module-level caches (persist for the lifetime of a Worker isolate)
// ==================================================================

let jwksCache = { keys: null, expiresAt: 0 };
const oauthCache = new Map(); // client_email → { token, expiresAt }
let saCache = { raw: null, parsed: null };

// ==================================================================
// Errors
// ==================================================================

class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

class UploadValidationError extends HttpError {
  constructor(message, extra = {}) {
    super(400, message, extra);
  }
}

// ==================================================================
// Response helpers
// ==================================================================

const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'POST, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type',
  'access-control-max-age': '86400',
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...CORS_HEADERS },
  });
}

function errorResponse(err) {
  if (err instanceof HttpError) {
    return jsonResponse({ status: 'error', error: err.message, ...err.extra }, err.status);
  }
  console.error('[roster-worker] unhandled error:', err && err.stack ? err.stack : err);
  return jsonResponse({ status: 'error', error: 'Internal server error.' }, 500);
}

// ==================================================================
// Encoding helpers
// ==================================================================

function utf8ToBytes(str) {
  return new TextEncoder().encode(str);
}

function bytesToB64url(bytes) {
  const arr = new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < arr.length; i += 1) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function utf8ToB64url(str) {
  return bytesToB64url(utf8ToBytes(str));
}

function b64urlToBytes(str) {
  const norm = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = norm.length % 4 === 0 ? norm : norm + '='.repeat(4 - (norm.length % 4));
  const bin = atob(pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToString(str) {
  return new TextDecoder().decode(b64urlToBytes(str));
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function safeBaseName(name) {
  return (
    String(name || 'roster')
      .replace(/[^a-zA-Z0-9_-]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 60) || 'roster'
  );
}

function generateDocId() {
  // Firestore-style 20-char alphanumeric id
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) out += chars[bytes[i] % 62];
  return out;
}

function strOrEmpty(v) {
  return v === undefined || v === null ? '' : String(v).trim();
}

// ==================================================================
// Service account loading / caching
// ==================================================================

/**
 * Read the service-account secret.
 *
 * Matches the convention used by edutraceug-auth-worker and
 * edutraceug-email-worker: the secret is named ACCOUNT-SERVICE-FIREBASE
 * (hyphenated — allowed for Cloudflare/Wrangler secrets, unlike Node env
 * vars). We also fall back to the underscore form so anything still
 * setting the older name keeps working during the transition.
 */
function getServiceAccount(env) {
  const raw =
    env['ACCOUNT-SERVICE-FIREBASE'] ||
    env.ACCOUNT_SERVICE_FIREBASE;

  if (!raw || !String(raw).trim()) {
    throw new HttpError(
      500,
      'ACCOUNT-SERVICE-FIREBASE is not configured (checked ACCOUNT-SERVICE-FIREBASE and ACCOUNT_SERVICE_FIREBASE).'
    );
  }
  if (saCache.raw === raw && saCache.parsed) return saCache.parsed;

  const text = String(raw).trim();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    try {
      parsed = JSON.parse(atob(text));
    } catch {
      throw new HttpError(
        500,
        'ACCOUNT-SERVICE-FIREBASE must be a service-account JSON object (raw or base64-encoded).'
      );
    }
  }

  if (!parsed.project_id || !parsed.client_email || !parsed.private_key) {
    throw new HttpError(
      500,
      'ACCOUNT-SERVICE-FIREBASE is missing project_id, client_email, or private_key.'
    );
  }

  saCache = { raw, parsed };
  return parsed;
}

// ==================================================================
// JWKS: Firebase ID token verification
// ==================================================================

async function getGoogleJwks() {
  const now = Date.now();
  if (jwksCache.keys && jwksCache.expiresAt > now) return jwksCache.keys;

  const res = await fetch(GOOGLE_JWKS_URL, { cf: { cacheTtl: 3600 } });
  if (!res.ok) {
    throw new HttpError(502, `Failed to fetch Google JWKS (${res.status}).`);
  }
  const body = await res.json();
  if (!body || !Array.isArray(body.keys)) {
    throw new HttpError(502, 'Google JWKS response was malformed.');
  }
  jwksCache = { keys: body.keys, expiresAt: now + JWKS_TTL_MS };
  return body.keys;
}

async function verifyFirebaseIdToken(idToken, projectId) {
  const parts = String(idToken || '').split('.');
  if (parts.length !== 3) throw new Error('Token is not a JWT.');
  const [headerB64, payloadB64, sigB64] = parts;

  const header = JSON.parse(b64urlToString(headerB64));
  const payload = JSON.parse(b64urlToString(payloadB64));

  if (header.alg !== 'RS256') throw new Error(`Unsupported alg: ${header.alg}`);
  if (!header.kid) throw new Error('Token header is missing kid.');

  const keys = await getGoogleJwks();
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('No matching JWK for token kid.');

  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const signingInput = utf8ToBytes(`${headerB64}.${payloadB64}`);
  const signature = b64urlToBytes(sigB64);

  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, signingInput);
  if (!valid) throw new Error('Signature verification failed.');

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now) throw new Error('Token expired.');
  if (payload.iss !== `https://securetoken.google.com/${projectId}`) {
    throw new Error('Bad token issuer.');
  }
  if (payload.aud !== projectId) throw new Error('Bad token audience.');
  if (!payload.sub || typeof payload.sub !== 'string') throw new Error('Token has no sub.');

  if (typeof payload.auth_time === 'number' && payload.auth_time > now + 60) {
    throw new Error('auth_time is in the future.');
  }

  return payload;
}

// ==================================================================
// Google OAuth2: service-account JWT → access token
// ==================================================================

async function importPrivateKey(pem) {
  const b64 = String(pem)
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s+/g, '');
  const der = base64ToBytes(b64);
  return crypto.subtle.importKey(
    'pkcs8',
    der,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

async function signJwtRs256(payload, privateKeyPem) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const headerB64 = utf8ToB64url(JSON.stringify(header));
  const payloadB64 = utf8ToB64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  const key = await importPrivateKey(privateKeyPem);
  const sigBuf = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    utf8ToBytes(signingInput)
  );

  return `${signingInput}.${bytesToB64url(sigBuf)}`;
}

async function getAccessToken(env, scope = FIRESTORE_SCOPE) {
  const sa = getServiceAccount(env);
  const cacheKey = `${sa.client_email}|${scope}`;
  const now = Math.floor(Date.now() / 1000);

  const cached = oauthCache.get(cacheKey);
  if (cached && cached.expiresAt > now + OAUTH_SAFETY_SECONDS) {
    return cached.token;
  }

  const jwt = await signJwtRs256(
    {
      iss: sa.client_email,
      scope,
      aud: OAUTH_TOKEN_URL,
      iat: now,
      exp: now + 3600,
    },
    sa.private_key
  );

  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: jwt,
  });

  const res = await fetch(OAUTH_TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new HttpError(502, `Google OAuth token exchange failed (${res.status}): ${text.slice(0, 200)}`);
  }

  const data = await res.json();
  if (!data.access_token) throw new HttpError(502, 'Google OAuth response missing access_token.');

  const expiresAt = now + (Number(data.expires_in) || 3600);
  oauthCache.set(cacheKey, { token: data.access_token, expiresAt });
  return data.access_token;
}

// ==================================================================
// Firestore REST — value encoding/decoding
// ==================================================================

function toFirestoreValue(v) {
  if (v === undefined || v === null) return { nullValue: null };
  if (typeof v === 'string') return { stringValue: v };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') {
    if (Number.isInteger(v)) return { integerValue: String(v) };
    return { doubleValue: v };
  }
  if (v instanceof Date) return { timestampValue: v.toISOString() };
  if (Array.isArray(v)) {
    return { arrayValue: { values: v.map(toFirestoreValue) } };
  }
  if (typeof v === 'object') {
    const fields = {};
    for (const [k, val] of Object.entries(v)) fields[k] = toFirestoreValue(val);
    return { mapValue: { fields } };
  }
  return { nullValue: null };
}

function fromFirestoreValue(fv) {
  if (!fv) return null;
  if ('nullValue' in fv) return null;
  if ('stringValue' in fv) return fv.stringValue;
  if ('booleanValue' in fv) return fv.booleanValue;
  if ('integerValue' in fv) return Number(fv.integerValue);
  if ('doubleValue' in fv) return fv.doubleValue;
  if ('timestampValue' in fv) return fv.timestampValue;
  if ('arrayValue' in fv) {
    const values = fv.arrayValue?.values || [];
    return values.map(fromFirestoreValue);
  }
  if ('mapValue' in fv) {
    const out = {};
    const fields = fv.mapValue?.fields || {};
    for (const [k, v] of Object.entries(fields)) out[k] = fromFirestoreValue(v);
    return out;
  }
  return null;
}

function toFirestoreFields(obj) {
  const fields = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined) continue;
    fields[k] = toFirestoreValue(v);
  }
  return fields;
}

function fromFirestoreDocument(doc) {
  const out = {};
  if (!doc || !doc.fields) return out;
  for (const [k, v] of Object.entries(doc.fields)) out[k] = fromFirestoreValue(v);
  return out;
}

// ==================================================================
// Firestore REST — resource paths and endpoints
// ==================================================================

function firestoreBase(env) {
  const sa = getServiceAccount(env);
  return `https://firestore.googleapis.com/v1/projects/${sa.project_id}/databases/(default)/documents`;
}

function docName(env, segments) {
  const sa = getServiceAccount(env);
  return `projects/${sa.project_id}/databases/(default)/documents/${segments.join('/')}`;
}

async function getFirestoreDocument(env, token, segments) {
  const url = `${firestoreBase(env)}/${segments.map(encodeURIComponent).join('/')}`;
  const res = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
  if (res.status === 404) return null;
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new HttpError(502, `Firestore GET failed (${res.status}): ${text.slice(0, 200)}`);
  }
  return res.json();
}

async function firestoreRunQuery(env, token, parentSegments, structuredQuery) {
  const parent = parentSegments.map(encodeURIComponent).join('/');
  const url = `${firestoreBase(env)}/${parent}:runQuery`;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ structuredQuery }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new HttpError(502, `Firestore runQuery failed (${res.status}): ${text.slice(0, 200)}`);
  }

  const rows = await res.json();
  if (!Array.isArray(rows)) return [];
  return rows.filter((r) => r && r.document).map((r) => r.document);
}

async function firestoreCommit(env, token, writes) {
  const sa = getServiceAccount(env);
  const url = `https://firestore.googleapis.com/v1/projects/${sa.project_id}/databases/(default)/documents:commit`;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ writes }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new HttpError(502, `Firestore commit failed (${res.status}): ${text.slice(0, 200)}`);
  }
  return res.json();
}

// ==================================================================
// Firestore write-queue (batches writes into :commit calls)
// ==================================================================

class WriteQueue {
  constructor(env, token, maxPerBatch = 400) {
    this.env = env;
    this.token = token;
    this.maxPerBatch = maxPerBatch;
    this.writes = [];
  }

  // Partial update — only the fields in `data` are touched.
  update(segments, data) {
    const fieldPaths = Object.keys(data);
    this.writes.push({
      update: {
        name: docName(this.env, segments),
        fields: toFirestoreFields(data),
      },
      updateMask: { fieldPaths },
    });
    return this.#maybeFlush();
  }

  // Strict create — fails if the document already exists.
  create(segments, data) {
    this.writes.push({
      update: {
        name: docName(this.env, segments),
        fields: toFirestoreFields(data),
      },
      currentDocument: { exists: false },
    });
    return this.#maybeFlush();
  }

  // Merge-set — creates if missing, overwrites only the fields in `data`.
  merge(segments, data) {
    const fieldPaths = Object.keys(data);
    this.writes.push({
      update: {
        name: docName(this.env, segments),
        fields: toFirestoreFields(data),
      },
      updateMask: { fieldPaths },
    });
    return this.#maybeFlush();
  }

  async #maybeFlush() {
    if (this.writes.length >= this.maxPerBatch) await this.flush();
  }

  async flush() {
    if (this.writes.length === 0) return;
    const chunk = this.writes;
    this.writes = [];
    await firestoreCommit(this.env, this.token, chunk);
  }
}

// ==================================================================
// Cloudmersive virus scan
// ==================================================================

async function scanFileForViruses(env, file) {
  if (!env.CLOUDMERSIVE_API_KEY) {
    throw new HttpError(500, 'CLOUDMERSIVE_API_KEY is not configured.');
  }

  const form = new FormData();
  form.append('inputFile', file, file.name || 'upload');

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);

  let res;
  try {
    res = await fetch(CLOUDMERSIVE_SCAN_URL, {
      method: 'POST',
      headers: { Apikey: env.CLOUDMERSIVE_API_KEY, Accept: 'application/json' },
      body: form,
      signal: controller.signal,
    });
  } catch (err) {
    throw new HttpError(502, `Virus scan service unreachable: ${err.message}`);
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new HttpError(
      502,
      `Virus scan service returned ${res.status}. ${detail.slice(0, 200)}`.trim()
    );
  }

  const data = await res.json().catch(() => ({}));
  const found = Array.isArray(data.FoundViruses) ? data.FoundViruses : [];
  const clean = data.CleanResult !== false && found.length === 0;

  return { clean, foundViruses: found };
}

// ==================================================================
// Cloudinary raw upload (signed, via REST)
// ==================================================================

async function cloudinarySignature(params, apiSecret) {
  const toSign =
    Object.keys(params)
      .sort()
      .map((k) => `${k}=${params[k]}`)
      .join('&') + apiSecret;

  const digest = await crypto.subtle.digest('SHA-1', utf8ToBytes(toSign));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function uploadRawToCloudinary(env, file, { folder }) {
  const cloudName = env.CLOUDINARY_CLOUD_NAME;
  const apiKey = env.CLOUDINARY_API_KEY;
  const apiSecret = env.CLOUDINARY_API_SECRET;

  if (!cloudName || !apiKey || !apiSecret) {
    throw new HttpError(500, 'Cloudinary credentials are not configured.');
  }

  const parsedExt = (() => {
    const name = file.name || 'roster.xlsx';
    const dot = name.lastIndexOf('.');
    return dot > 0 ? name.slice(dot).toLowerCase() : '.xlsx';
  })();

  const publicId = `${safeBaseName((file.name || 'roster').replace(/\.[^.]+$/, ''))}_${Date.now()}${parsedExt}`;
  const timestamp = Math.floor(Date.now() / 1000);

  const signedParams = {
    folder,
    public_id: publicId,
    timestamp: String(timestamp),
  };
  const signature = await cloudinarySignature(signedParams, apiSecret);

  const form = new FormData();
  form.append('file', file, file.name || `roster${parsedExt}`);
  form.append('api_key', apiKey);
  form.append('timestamp', signedParams.timestamp);
  form.append('public_id', signedParams.public_id);
  form.append('folder', signedParams.folder);
  form.append('signature', signature);

  const res = await fetch(
    `https://api.cloudinary.com/v1_1/${cloudName}/raw/upload`,
    { method: 'POST', body: form }
  );

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new HttpError(
      502,
      `Cloudinary upload failed (${res.status}): ${text.slice(0, 200)}`
    );
  }

  const data = await res.json();
  if (!data.secure_url) throw new HttpError(502, 'Cloudinary response missing secure_url.');
  return data;
}

// ==================================================================
// SheetJS parser — header detection & row extraction (kept unchanged)
// ==================================================================

const CANONICAL_FIELDS = [
  'firstName',
  'lastName',
  'class',
  'gender',
  'stream',
  'subject',
  'extraDetail',
];

const POSITIONAL_ORDER = [...CANONICAL_FIELDS];

const ALIASES = {
  firstName: ['firstname', 'givenname', 'forename', 'first', 'fname', 'christianname'],
  lastName: ['lastname', 'surname', 'familyname', 'secondname', 'last', 'lname'],
  class: ['class', 'classname', 'grade', 'form', 'level', 'year'],
  gender: ['gender', 'sex'],
  stream: ['stream', 'section', 'arm', 'division'],
  subject: ['subject', 'subjects', 'subjectcombination', 'combination', 'papers'],
  extraDetail: [
    'extradetail', 'extra', 'notes', 'note', 'disambiguation',
    'remark', 'remarks', 'comment', 'comments',
  ],
};

function normalizeHeader(value) {
  return String(value ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

function cellAt(values, index) {
  if (index === undefined || index === null || index < 0) return '';
  const raw = values[index];
  if (raw === undefined || raw === null) return '';
  return String(raw).replace(/\s+/g, ' ').trim();
}

function detectColumns(matrix) {
  const scanLimit = Math.min(matrix.length, 15);
  let best = null;

  for (let r = 0; r < scanLimit; r += 1) {
    const row = matrix[r] || [];
    const map = {};
    let score = 0;

    for (let c = 0; c < row.length; c += 1) {
      const key = normalizeHeader(row[c]);
      if (!key) continue;

      for (const field of CANONICAL_FIELDS) {
        if (map[field] !== undefined) continue;
        if (ALIASES[field].includes(key)) {
          map[field] = c;
          score += 1;
          break;
        }
      }
    }

    const hasCore =
      map.firstName !== undefined &&
      map.lastName !== undefined &&
      map.class !== undefined;

    if (hasCore && (!best || score > best.score)) {
      best = { headerRowIndex: r, map, score, positional: false };
    }
  }

  if (best) return best;

  const map = {};
  POSITIONAL_ORDER.forEach((field, i) => {
    map[field] = i;
  });
  return { headerRowIndex: -1, map, score: 0, positional: true };
}

function parseWorkbook(buffer) {
  let workbook;
  try {
    workbook = XLSX.read(new Uint8Array(buffer), { type: 'array', cellDates: false });
  } catch (err) {
    throw new UploadValidationError(
      `Could not read the spreadsheet: ${err.message}. Is the file corrupt or password-protected?`
    );
  }

  if (!workbook.SheetNames || workbook.SheetNames.length === 0) {
    throw new UploadValidationError('The workbook contains no sheets.');
  }

  const sheetName = workbook.SheetNames[0];
  const sheet = workbook.Sheets[sheetName];

  const matrix = XLSX.utils.sheet_to_json(sheet, {
    header: 1,
    defval: '',
    blankrows: false,
    raw: false,
  });

  return { sheetName, matrix };
}

function readRosterRows(buffer) {
  const { sheetName, matrix } = parseWorkbook(buffer);

  if (matrix.length === 0) {
    throw new UploadValidationError('The sheet is empty.');
  }

  const columns = detectColumns(matrix);
  const startIndex = columns.headerRowIndex + 1;
  const rows = [];

  for (let i = startIndex; i < matrix.length; i += 1) {
    const raw = matrix[i] || [];
    const isBlank = !raw.some((v) => String(v ?? '').trim() !== '');
    if (isBlank) continue;

    rows.push({
      excelRow: i + 1,
      firstName: cellAt(raw, columns.map.firstName),
      lastName: cellAt(raw, columns.map.lastName),
      class: cellAt(raw, columns.map.class),
      gender: cellAt(raw, columns.map.gender),
      stream: cellAt(raw, columns.map.stream),
      subject: cellAt(raw, columns.map.subject),
      extraDetail: cellAt(raw, columns.map.extraDetail),
    });
  }

  if (rows.length === 0) {
    throw new UploadValidationError(
      'No data rows found. The file must contain a header row (first name, last name, class, subject, ...) followed by data rows.'
    );
  }

  return { sheetName, columns, rows };
}

// ==================================================================
// Row validation + merge logic (kept unchanged)
// ==================================================================

function splitList(v) {
  return String(v || '')
    .split(/[,;]+/)
    .map((s) => s.replace(/\s+/g, ' ').trim())
    .filter(Boolean);
}

function mergeList(a, b) {
  const out = Array.isArray(a) ? [...a] : [];
  for (const item of b || []) {
    if (!out.some((x) => String(x).toLowerCase() === String(item).toLowerCase())) {
      out.push(item);
    }
  }
  return out;
}

function buildDesired(recordType, v) {
  if (recordType === 'teacher') {
    return {
      recordType,
      firstName: v.firstName,
      lastName: v.lastName,
      gender: v.gender,
      extraDetail: v.extraDetail,
      subjects: v.subjects,
      classes: [v.class],
    };
  }
  return { recordType, ...v };
}

function validateAndNormalize(row, fileClass, fileStream) {
  const errors = [];

  const firstName = row.firstName;
  const lastName = row.lastName;
  const className = row.class || fileClass || '';
  const stream = row.stream || fileStream || '';
  const subjects = splitList(row.subject);
  const extraDetail = row.extraDetail;

  let gender = row.gender || '';

  if (!firstName) errors.push('first name is required');
  if (!lastName) errors.push('last name is required');
  if (!className) errors.push('class is required');
  if (subjects.length === 0) errors.push('subject is required');

  if (gender) {
    const g = gender.toLowerCase();
    if (g === 'male' || g === 'm') gender = 'Male';
    else if (g === 'female' || g === 'f') gender = 'Female';
    else errors.push('gender must be Male or Female');
  }

  if (errors.length > 0) return { errors };

  return {
    errors: [],
    value: {
      firstName,
      lastName,
      class: className,
      gender,
      stream,
      subjects,
      extraDetail: extraDetail || '',
    },
  };
}

function localKey(recordType, value) {
  if (recordType === 'teacher') {
    return ['teacher', value.firstName, value.lastName].join('\u0000');
  }
  return [recordType, value.firstName, value.lastName, value.class, value.stream].join('\u0000');
}

function fieldFilter(fieldPath, op, value) {
  return {
    fieldFilter: {
      field: { fieldPath },
      op,
      value,
    },
  };
}

async function queryCandidates(env, token, schoolId, recordType, desired) {
  const filters = [
    fieldFilter('recordType', 'EQUAL', { stringValue: recordType }),
    fieldFilter('firstName', 'EQUAL', { stringValue: desired.firstName }),
    fieldFilter('lastName', 'EQUAL', { stringValue: desired.lastName }),
  ];

  if (recordType === 'student') {
    filters.push(fieldFilter('class', 'EQUAL', { stringValue: desired.class }));
    if (desired.stream) {
      filters.push(fieldFilter('stream', 'EQUAL', { stringValue: desired.stream }));
    }
  }

  const where = { compositeFilter: { op: 'AND', filters } };

  const structuredQuery = {
    from: [{ collectionId: 'roster' }],
    where,
    limit: 10,
  };

  return firestoreRunQuery(env, token, ['schools', schoolId], structuredQuery);
}

function pickBestCandidate(docs, desired) {
  if (!docs || docs.length === 0) return null;

  const toEntry = (doc) => {
    const id = doc.name.split('/').pop();
    return { id, data: fromFirestoreDocument(doc) };
  };

  const exact = docs.find((doc) => {
    const d = fromFirestoreDocument(doc);
    return DATA_FIELDS.every((f) => String(d[f] ?? '') === String(desired[f] ?? ''));
  });
  if (exact) return toEntry(exact);

  if (!desired.stream) {
    const noStream = docs.find((doc) => !fromFirestoreDocument(doc).stream);
    if (noStream) return toEntry(noStream);
  }

  return toEntry(docs[0]);
}

function computeDiff(existingData, desired) {
  const diff = {};
  for (const field of DATA_FIELDS) {
    const current = String(existingData[field] ?? '');
    const next = String(desired[field] ?? '');
    if (current !== next) diff[field] = desired[field];
  }
  for (const f of ['subjects', 'classes']) {
    if (!desired[f]) continue;
    const merged = mergeList(existingData[f], desired[f]);
    const before = Array.isArray(existingData[f]) ? existingData[f].length : 0;
    if (merged.length !== before) diff[f] = merged;
  }
  return diff;
}

async function processRosterRows({
  env,
  token,
  schoolId,
  recordType,
  fileClass = '',
  fileStream = '',
  rows,
  offset,
  batchId,
  cloudinaryUrl,
  uid,
}) {
  if (!RECORD_TYPES.has(recordType)) {
    throw new Error(`Invalid recordType: ${recordType}`);
  }

  const slice = rows.slice(offset, offset + MAX_ROWS_PER_CALL);
  const nextOffset = offset + slice.length;
  const remaining = Math.max(0, rows.length - nextOffset);

  const queue = new WriteQueue(env, token);

  let created = 0;
  let updated = 0;
  let unchanged = 0;
  const rejected = [];
  const now = new Date();

  // Group rows so one student/teacher = one record, with all subjects gathered.
  const groups = new Map();
  for (const row of slice) {
    const { errors, value } = validateAndNormalize(row, fileClass, fileStream);

    if (errors.length > 0) {
      rejected.push({ row: row.excelRow, reason: errors.join('; ') });
      continue;
    }

    const desired = buildDesired(recordType, value);
    const key = localKey(recordType, desired);
    const g = groups.get(key);

    if (!g) {
      groups.set(key, desired);
    } else {
      g.subjects = mergeList(g.subjects, desired.subjects);
      if (recordType === 'teacher') g.classes = mergeList(g.classes, desired.classes);
      if (!g.gender && desired.gender) g.gender = desired.gender;
    }
  }

  for (const desired of groups.values()) {
    const docs = await queryCandidates(env, token, schoolId, recordType, desired);
    const existing = pickBestCandidate(docs, desired);

    if (existing) {
      const diff = computeDiff(existing.data, desired);

      if (Object.keys(diff).length === 0) {
        unchanged += 1;
        continue;
      }

      await queue.update(['schools', schoolId, 'roster', existing.id], {
        ...diff,
        batchId,
        updatedAt: now,
      });
      updated += 1;
    } else {
      const docId = generateDocId();
      const data = {
        ...desired,
        batchId,
        cloudinaryUrl,
        createdBy: uid,
        createdAt: now,
        updatedAt: now,
      };

      await queue.create(['schools', schoolId, 'roster', docId], data);
      created += 1;
    }
  }

  await queue.flush();

  return {
    processed: slice.length,
    remaining,
    nextOffset,
    created,
    updated,
    unchanged,
    rejected,
  };
}

// ==================================================================
// File-extension/MIME gate (replaces multer's fileFilter)
// ==================================================================

function validateFileMetadata(file) {
  const original = file.name || '';
  const dot = original.lastIndexOf('.');
  const ext = dot >= 0 ? original.slice(dot).toLowerCase() : '';

  if (ext === '.xlsb') {
    throw new UploadValidationError(
      '".xlsb" files are not supported. Please re-save as .xlsx, .xls, .xlsm, .xltx, .xltm or .csv.'
    );
  }

  if (!ACCEPTED_EXTENSIONS.includes(ext)) {
    throw new UploadValidationError(
      `Unsupported file type "${ext || '(no extension)'}". Accepted: ${ACCEPTED_EXTENSIONS.join(', ')}.`
    );
  }

  const mime = String(file.type || '').toLowerCase();
  if (!ACCEPTED_MIME.has(mime)) {
    throw new UploadValidationError(
      `Unsupported content type "${file.type}". Please upload an Excel or CSV file.`
    );
  }
}

// ==================================================================
// Batch (rosterUploads) helpers
// ==================================================================

async function findRecentBatch(env, token, schoolId, { uid, recordType, fileClass, fileStream }) {
  const structuredQuery = {
    from: [{ collectionId: 'rosterUploads' }],
    where: fieldFilter('uploadedBy', 'EQUAL', { stringValue: uid }),
    limit: 50,
  };

  const docs = await firestoreRunQuery(env, token, ['schools', schoolId], structuredQuery);
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;

  let best = null;
  let bestTs = -1;

  for (const doc of docs) {
    const d = fromFirestoreDocument(doc);
    if (d.recordType !== recordType) continue;
    if (strOrEmpty(d.class) !== strOrEmpty(fileClass)) continue;
    if (strOrEmpty(d.stream) !== strOrEmpty(fileStream)) continue;

    const ts = typeof d.uploadedAt === 'string' ? Date.parse(d.uploadedAt) : 0;
    if (!Number.isFinite(ts) || ts < cutoff) continue;
    if (ts > bestTs) {
      bestTs = ts;
      best = { id: doc.name.split('/').pop(), data: d };
    }
  }

  return best;
}

// ==================================================================
// /upload-roster handler
// ==================================================================

async function handleUploadRoster(request, env) {
  /* ---- 0. Auth ---- */
  const authHeader = request.headers.get('authorization') || '';
  const authMatch = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!authMatch) {
    throw new HttpError(
      401,
      'Missing Authorization header. Expected: Authorization: Bearer <Firebase ID token>'
    );
  }

  const sa = getServiceAccount(env);
  const projectId = sa.project_id;

  let claims;
  try {
    claims = await verifyFirebaseIdToken(authMatch[1].trim(), projectId);
  } catch (err) {
    throw new HttpError(401, `Invalid or expired ID token. (${err.message})`);
  }

  const user = {
    uid: claims.sub,
    role: claims.role || null,
    schoolId: claims.schoolId || null,
  };

  if (user.role !== 'schoolAdmin') {
    throw new HttpError(403, 'This endpoint requires role "schoolAdmin".');
  }

  /* ---- 1. Multipart parse ---- */
  let form;
  try {
    form = await request.formData();
  } catch (err) {
    throw new UploadValidationError(`Could not parse multipart body: ${err.message}`);
  }

  const file = form.get('file');
  if (!file || typeof file === 'string' || typeof file.arrayBuffer !== 'function') {
    throw new UploadValidationError(
      '"file" is required (multipart/form-data, field name "file").'
    );
  }

  const schoolId = strOrEmpty(form.get('schoolId'));
  const fileClass = strOrEmpty(form.get('class'));
  const fileStream = strOrEmpty(form.get('stream'));
  const recordType = strOrEmpty(form.get('recordType')).toLowerCase();
  const providedBatchId = strOrEmpty(form.get('batchId')) || null;

  const offsetRaw = strOrEmpty(form.get('offset'));
  const offset = offsetRaw === '' ? 0 : Number.parseInt(offsetRaw, 10);

  /* ---- 2. Validate ---- */
  if (!schoolId) throw new UploadValidationError('"schoolId" is required.');
  if (user.schoolId !== schoolId) {
    throw new HttpError(403, "Your token's schoolId does not match the requested schoolId.");
  }
  if (!RECORD_TYPES.has(recordType)) {
    throw new UploadValidationError('"recordType" must be either "student" or "teacher".');
  }
  if (!Number.isFinite(offset) || offset < 0) {
    throw new UploadValidationError('"offset" must be a non-negative integer.');
  }

  const maxBytes =
    (Number(env.MAX_FILE_SIZE_MB) || DEFAULT_MAX_FILE_SIZE_MB) * 1024 * 1024;
  if (file.size > maxBytes) {
    throw new UploadValidationError(
      `File is too large (${file.size} bytes; max ${maxBytes}). Please split the roster into smaller files.`
    );
  }

  validateFileMetadata(file);

  /* ---- 3. Virus scan ---- */
  const scan = await scanFileForViruses(env, file);
  if (!scan.clean) {
    throw new HttpError(400, 'File failed the virus scan and was not processed.', {
      foundViruses: scan.foundViruses,
    });
  }

  /* ---- 4. OAuth token for Firestore ---- */
  const token = await getAccessToken(env, FIRESTORE_SCOPE);

  /* ---- 5. Archival copy on Cloudinary ---- */
  let batchId = providedBatchId;
  let cloudinaryUrl = null;
  let batchDocExists = false;

  if (offset > 0 && batchId) {
    const snap = await getFirestoreDocument(env, token, [
      'schools', schoolId, 'rosterUploads', batchId,
    ]);
    if (snap) {
      cloudinaryUrl = fromFirestoreDocument(snap).cloudinaryUrl || null;
      batchDocExists = Boolean(cloudinaryUrl);
    }
  }

  if (offset > 0 && !cloudinaryUrl) {
    const found = await findRecentBatch(env, token, schoolId, {
      uid: user.uid,
      recordType,
      fileClass,
      fileStream,
    });
    if (found) {
      batchId = found.id;
      cloudinaryUrl = found.data.cloudinaryUrl || null;
      batchDocExists = Boolean(cloudinaryUrl);
    }
  }

  if (!cloudinaryUrl) {
    const uploaded = await uploadRawToCloudinary(env, file, {
      folder: `edutraceug/roster-uploads/${schoolId}`,
    });
    cloudinaryUrl = uploaded.secure_url;
    if (!batchId) batchId = generateDocId();
  }

  /* ---- 6. Parse rows ---- */
  const buffer = await file.arrayBuffer();
  const { sheetName, columns, rows } = readRosterRows(buffer);

  /* ---- 7. Process rows ---- */
  const report = await processRosterRows({
    env,
    token,
    schoolId,
    recordType,
    fileClass,
    fileStream,
    rows,
    offset,
    batchId,
    cloudinaryUrl,
    uid: user.uid,
  });

  /* ---- 8. Batch record (create on first call, roll counters otherwise) ---- */
  const now = new Date();
  const batchPath = ['schools', schoolId, 'rosterUploads', batchId];

  if (offset === 0 && !batchDocExists) {
    const initial = {
      cloudinaryUrl,
      recordType,
      class: fileClass,
      stream: fileStream,
      uploadedBy: user.uid,
      uploadedAt: now,
      fileName: file.name || '',
      fileSize: file.size,
      sheetName,
      totalRows: rows.length,
      headerRowIndex: columns.headerRowIndex,
      status: report.remaining === 0 ? 'complete' : 'in_progress',
      createdCount: report.created,
      updatedCount: report.updated,
      unchangedCount: report.unchanged,
      rejectedCount: report.rejected.length,
      lastProcessedOffset: report.nextOffset,
    };
    if (report.remaining === 0) initial.completedAt = now;

    await firestoreCommit(env, token, [
      {
        update: {
          name: docName(env, batchPath),
          fields: toFirestoreFields(initial),
        },
        currentDocument: { exists: false },
      },
    ]);
  } else {
    const snap = await getFirestoreDocument(env, token, batchPath);
    const existing = snap ? fromFirestoreDocument(snap) : {};

    const rollup = {
      cloudinaryUrl,
      createdCount: (Number(existing.createdCount) || 0) + report.created,
      updatedCount: (Number(existing.updatedCount) || 0) + report.updated,
      unchangedCount: (Number(existing.unchangedCount) || 0) + report.unchanged,
      rejectedCount: (Number(existing.rejectedCount) || 0) + report.rejected.length,
      lastProcessedOffset: report.nextOffset,
    };
    if (report.remaining === 0) {
      rollup.status = 'complete';
      rollup.completedAt = now;
    }

    await firestoreCommit(env, token, [
      {
        update: {
          name: docName(env, batchPath),
          fields: toFirestoreFields(rollup),
        },
        updateMask: { fieldPaths: Object.keys(rollup) },
      },
    ]);
  }

  /* ---- 9. Response ---- */
  return jsonResponse({
    status: 'ok',
    processed: report.processed,
    remaining: report.remaining,
    nextOffset: report.nextOffset,
    created: report.created,
    updated: report.updated,
    unchanged: report.unchanged,
    rejected: report.rejected,
    batchId,
  });
}

// ==================================================================
// Worker entry point
// ==================================================================

export default {
  async fetch(request, env, _ctx) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (url.pathname === '/health') {
      return jsonResponse({ status: 'ok', service: 'edutraceug-roster-worker' });
    }

    if (url.pathname === '/upload-roster' && request.method === 'POST') {
      try {
        return await handleUploadRoster(request, env);
      } catch (err) {
        return errorResponse(err);
      }
    }

    return jsonResponse(
      { status: 'error', error: `Not found: ${request.method} ${url.pathname}` },
      404
    );
  },
};
