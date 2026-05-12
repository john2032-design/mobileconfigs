const { createPool } = require('@vercel/postgres')
const crypto = require('crypto')

const connectionString = process.env.APIKey_POSTGRES_URL
if (!connectionString) {
  console.error('Missing APIKey_POSTGRES_URL environment variable')
}

const pool = createPool({ connectionString })

const BOT_SECRET = process.env.BOT_SECRET || 'e95eefb03ea57cc5d6810a849c51b4b5fd88b7fbf764a73063d2bcf35b3ad7fc'

function generateKey() {
  return crypto.randomBytes(16).toString('hex')
}

async function ensureTable() {
  try {
    await pool.sql`
      CREATE TABLE IF NOT EXISTS api_keys (
        key TEXT PRIMARY KEY,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        active INT DEFAULT 1
      )
    `
    const columns = await pool.sql`
      SELECT column_name FROM information_schema.columns 
      WHERE table_name = 'api_keys'
    `
    const existing = columns.rows.map(r => r.column_name)
    if (!existing.includes('user_id')) {
      await pool.sql`ALTER TABLE api_keys ADD COLUMN user_id TEXT`
    }
    if (!existing.includes('key_type')) {
      await pool.sql`ALTER TABLE api_keys ADD COLUMN key_type TEXT DEFAULT '24h'`
    }
  } catch (err) {
    console.error('Table creation/migration error:', err)
    throw err
  }
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  if (req.method === 'OPTIONS') return res.status(200).end()

  try {
    await ensureTable()
  } catch (err) {
    return res.status(500).json({ error: 'Database connection failed', details: err.message })
  }

  const url = new URL(req.url, `http://${req.headers.host}`)
  const path = url.pathname.replace(/^\/api\/key/, '')

  if (req.method === 'POST' && path === '/generate') {
    const authHeader = req.headers.authorization
    if (!authHeader || authHeader !== `Bearer ${BOT_SECRET}`) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    const { user_id, type } = req.body
    if (!user_id) {
      return res.status(400).json({ error: 'user_id required' })
    }

    const keyType = type === '78h' ? '78h' 
      : (type === 'infinite' ? 'infinite' 
        : (type === '1month' ? '1month' 
          : (type === '1year' ? '1year' : '24h')))

    const now = Math.floor(Date.now() / 1000)
    let expiresAt
    if (keyType === 'infinite') {
      expiresAt = 2147483647
    } else if (keyType === '78h') {
      expiresAt = now + 280800
    } else if (keyType === '1month') {
      expiresAt = now + 2592000
    } else if (keyType === '1year') {
      expiresAt = now + 31536000
    } else {
      expiresAt = now + 86400
    }

    try {
      const existing = await pool.sql`
        SELECT key, expires_at, key_type FROM api_keys 
        WHERE user_id = ${user_id} AND active = 1 AND expires_at > ${now}
      `

      if (existing.rowCount > 0) {
        const row = existing.rows[0]
        return res.json({
          key: row.key,
          expires_at: row.expires_at,
          key_type: row.key_type,
          existing: true
        })
      }

      const key = generateKey()

      await pool.sql`
        INSERT INTO api_keys (key, user_id, created_at, expires_at, key_type)
        VALUES (${key}, ${user_id}, ${now}, ${expiresAt}, ${keyType})
      `

      return res.json({ key, expires_at: expiresAt, key_type: keyType, existing: false })
    } catch (err) {
      console.error('Key generation DB error:', err)
      return res.status(500).json({ error: 'Failed to generate key', details: err.message })
    }
  }

  if (req.method === 'POST' && path === '/validate') {
    const { key } = req.body
    if (!key) {
      return res.status(400).json({ error: 'Key required' })
    }

    try {
      const now = Math.floor(Date.now() / 1000)
      const result = await pool.sql`
        SELECT key, expires_at, active, key_type FROM api_keys WHERE key = ${key}
      `

      if (result.rowCount === 0) {
        return res.json({ valid: false, reason: 'invalid_key' })
      }

      const row = result.rows[0]
      if (!row.active) {
        return res.json({ valid: false, reason: 'inactive' })
      }
      if (row.expires_at < now) {
        return res.json({ valid: false, reason: 'expired', expires_at: row.expires_at, key_type: row.key_type })
      }

      return res.json({ valid: true, expires_at: row.expires_at, key_type: row.key_type })
    } catch (err) {
      console.error('Validation error:', err)
      return res.status(500).json({ error: 'Database error', details: err.message })
    }
  }

  if (req.method === 'POST' && path === '/validate-hwid') {
    const { key, hwidHash, deviceHash, userAgent, ip, fingerprint } = req.body
    if (!key) {
      return res.status(400).json({ valid: false, reason: 'Key required' })
    }

    const HWID_API_BASE = 'https://vortixworld-end.vercel.app'
    const INTERNAL_SECRET = process.env.HWID_RESET_SECRET || '7f3d8a2e4b6c9f1d3a5e7c9b2d4f6a8c0e1d3f5a7b9c1e3d5f7a9b1c3e5d7f9'

    try {
      const now = Math.floor(Date.now() / 1000)
      const keyResult = await pool.sql`
        SELECT key, active, expires_at FROM api_keys WHERE key = ${key}
      `
      if (keyResult.rowCount === 0) {
        return res.status(404).json({ valid: false, reason: 'Key not found' })
      }
      const keyRow = keyResult.rows[0]
      if (!keyRow.active) {
        return res.status(400).json({ valid: false, reason: 'Key inactive' })
      }
      if (keyRow.expires_at < now) {
        return res.status(400).json({ valid: false, reason: 'Key expired' })
      }

      const identityCheckRes = await fetch(`${HWID_API_BASE}/api/hwid/identity-check`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${INTERNAL_SECRET}`
        },
        body: JSON.stringify({ apiKey: key, hwidHash, deviceHash, userAgent, ip, fingerprint })
      })

      if (!identityCheckRes.ok) {
        const errData = await identityCheckRes.json().catch(() => ({}))
        return res.status(identityCheckRes.status).json({
          valid: false,
          reason: errData.reason || 'identity_check_failed'
        })
      }

      const identityData = await identityCheckRes.json()
      return res.status(200).json(identityData)
    } catch (err) {
      console.error('validate-hwid error:', err)
      return res.status(500).json({ valid: false, reason: 'Internal error', details: err.message })
    }
  }

  if (req.method === 'POST' && path === '/reset-hwid') {
    const { key } = req.body
    if (!key) {
      return res.status(400).json({ error: 'Key required' })
    }

    const HWID_API_BASE = 'https://vortixworld-end.vercel.app'
    const HWID_RESET_SECRET = process.env.HWID_RESET_SECRET || BOT_SECRET

    try {
      const now = Math.floor(Date.now() / 1000)
      const keyResult = await pool.sql`
        SELECT key, active, expires_at FROM api_keys WHERE key = ${key}
      `
      if (keyResult.rowCount === 0) {
        return res.status(404).json({ error: 'Key not found' })
      }
      const keyRow = keyResult.rows[0]
      if (!keyRow.active) {
        return res.status(400).json({ error: 'Key is inactive' })
      }
      if (keyRow.expires_at < now) {
        return res.status(400).json({ error: 'Key is expired' })
      }

      const hwidRes = await fetch(`${HWID_API_BASE}/api/hwid/reset`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${HWID_RESET_SECRET}`
        },
        body: JSON.stringify({ apiKey: key })
      })

      const hwidData = await hwidRes.json()
      if (!hwidRes.ok) {
        return res.status(hwidRes.status).json({ error: hwidData.message || 'HWID reset failed' })
      }

      return res.json({ success: true, message: 'HWID binding cleared' })
    } catch (err) {
      console.error('HWID reset error:', err)
      return res.status(500).json({ error: 'Failed to reset HWID', details: err.message })
    }
  }

  if (req.method === 'POST' && path === '/renew') {
    const authHeader = req.headers.authorization
    if (!authHeader || authHeader !== `Bearer ${BOT_SECRET}`) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    const { key } = req.body
    if (!key) {
      return res.status(400).json({ error: 'Key required' })
    }

    try {
      const now = Math.floor(Date.now() / 1000)
      const result = await pool.sql`
        SELECT key, key_type, active FROM api_keys WHERE key = ${key}
      `

      if (result.rowCount === 0) {
        return res.status(404).json({ error: 'Key not found' })
      }

      const row = result.rows[0]
      if (!row.active) {
        return res.status(400).json({ error: 'Key is inactive' })
      }
      if (row.key_type === 'infinite') {
        return res.status(400).json({ error: 'Infinite keys cannot be renewed' })
      }

      let duration
      if (row.key_type === '78h') duration = 280800
      else if (row.key_type === '1month') duration = 2592000
      else if (row.key_type === '1year') duration = 31536000
      else duration = 86400

      const newExpiresAt = now + duration

      await pool.sql`
        UPDATE api_keys SET expires_at = ${newExpiresAt}
        WHERE key = ${key}
      `

      return res.json({ success: true, expires_at: newExpiresAt, key_type: row.key_type })
    } catch (err) {
      console.error('Key renewal error:', err)
      return res.status(500).json({ error: 'Failed to renew key', details: err.message })
    }
  }

  if (req.method === 'POST' && path === '/delete') {
    const authHeader = req.headers.authorization
    if (!authHeader || authHeader !== `Bearer ${BOT_SECRET}`) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    const { user_id } = req.body
    if (!user_id) {
      return res.status(400).json({ error: 'user_id required' })
    }

    try {
      const now = Math.floor(Date.now() / 1000)
      const result = await pool.sql`
        UPDATE api_keys SET active = 0
        WHERE user_id = ${user_id} AND active = 1 AND expires_at > ${now}
        RETURNING key
      `

      const deletedCount = result.rowCount
      return res.json({ success: true, deleted: deletedCount })
    } catch (err) {
      console.error('Key deletion error:', err)
      return res.status(500).json({ error: 'Failed to delete keys', details: err.message })
    }
  }

  if (req.method === 'POST' && path === '/clear-expired') {
    const authHeader = req.headers.authorization
    if (!authHeader || authHeader !== `Bearer ${BOT_SECRET}`) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    try {
      const now = Math.floor(Date.now() / 1000)
      const result = await pool.sql`
        UPDATE api_keys SET active = 0
        WHERE active = 1 AND expires_at < ${now}
        RETURNING key
      `

      return res.json({ success: true, cleared: result.rowCount })
    } catch (err) {
      console.error('Clear expired error:', err)
      return res.status(500).json({ error: 'Failed to clear expired keys', details: err.message })
    }
  }

  if (req.method === 'GET' && path.startsWith('/info/')) {
    const key = path.split('/')[2]
    if (!key) {
      return res.status(400).json({ error: 'Key required' })
    }

    try {
      const now = Math.floor(Date.now() / 1000)
      const result = await pool.sql`
        SELECT key, user_id, created_at, expires_at, active, key_type FROM api_keys WHERE key = ${key}
      `

      if (result.rowCount === 0) {
        return res.status(404).json({ error: 'Key not found' })
      }

      const row = result.rows[0]
      const valid = row.active && row.expires_at > now
      return res.json({
        key: row.key,
        user_id: row.user_id,
        created_at: row.created_at,
        expires_at: row.expires_at,
        active: row.active,
        key_type: row.key_type,
        valid
      })
    } catch (err) {
      console.error('Info error:', err)
      return res.status(500).json({ error: 'Database error', details: err.message })
    }
  }

  res.status(404).json({ error: 'Not found' })
}