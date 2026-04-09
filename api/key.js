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
    const columnCheck = await pool.sql`
      SELECT column_name FROM information_schema.columns 
      WHERE table_name = 'api_keys' AND column_name = 'user_id'
    `
    if (columnCheck.rowCount === 0) {
      await pool.sql`ALTER TABLE api_keys ADD COLUMN user_id TEXT`
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

    const { user_id } = req.body
    if (!user_id) {
      return res.status(400).json({ error: 'user_id required' })
    }

    try {
      const now = Math.floor(Date.now() / 1000)

      const existing = await pool.sql`
        SELECT key, expires_at FROM api_keys 
        WHERE user_id = ${user_id} AND active = 1 AND expires_at > ${now}
      `

      if (existing.rowCount > 0) {
        const row = existing.rows[0]
        return res.json({ key: row.key, expires_at: row.expires_at, existing: true })
      }

      const key = generateKey()
      const expiresAt = now + 86400

      await pool.sql`
        INSERT INTO api_keys (key, user_id, created_at, expires_at)
        VALUES (${key}, ${user_id}, ${now}, ${expiresAt})
      `

      return res.json({ key, expires_at: expiresAt, existing: false })
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
        SELECT key, expires_at, active FROM api_keys WHERE key = ${key}
      `

      if (result.rowCount === 0) {
        return res.json({ valid: false, reason: 'invalid_key' })
      }

      const row = result.rows[0]
      if (!row.active) {
        return res.json({ valid: false, reason: 'inactive' })
      }
      if (row.expires_at < now) {
        return res.json({ valid: false, reason: 'expired', expires_at: row.expires_at })
      }

      return res.json({ valid: true, expires_at: row.expires_at })
    } catch (err) {
      console.error('Validation error:', err)
      return res.status(500).json({ error: 'Database error', details: err.message })
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
        SELECT key, user_id, created_at, expires_at, active FROM api_keys WHERE key = ${key}
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
        valid
      })
    } catch (err) {
      console.error('Info error:', err)
      return res.status(500).json({ error: 'Database error', details: err.message })
    }
  }

  res.status(404).json({ error: 'Not found' })
}