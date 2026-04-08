const { sql } = require('@vercel/postgres')
const crypto = require('crypto')

const BOT_SECRET = 'e95eefb03ea57cc5d6810a849c51b4b5fd88b7fbf764a73063d2bcf35b3ad7fc'

function generateKey() {
  return crypto.randomBytes(16).toString('hex')
}

async function ensureTable() {
  await sql`
    CREATE TABLE IF NOT EXISTS api_keys (
      key TEXT PRIMARY KEY,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      active INT DEFAULT 1
    )
  `
}

module.exports = async (req, res) => {
  await ensureTable()

  const url = new URL(req.url, `http://${req.headers.host}`)
  const path = url.pathname.replace(/^\/api\/key/, '')

  if (req.method === 'POST' && path === '/generate') {
    const authHeader = req.headers.authorization
    if (!authHeader || authHeader !== `Bearer ${BOT_SECRET}`) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    const key = generateKey()
    const now = Math.floor(Date.now() / 1000)
    const expiresAt = now + 86400

    await sql`
      INSERT INTO api_keys (key, created_at, expires_at)
      VALUES (${key}, ${now}, ${expiresAt})
    `

    return res.json({ key, expires_at: expiresAt })
  }

  if (req.method === 'POST' && path === '/validate') {
    const { key } = req.body
    if (!key) {
      return res.status(400).json({ error: 'Key required' })
    }

    const now = Math.floor(Date.now() / 1000)
    const result = await sql`
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
  }

  if (req.method === 'GET' && path.startsWith('/info/')) {
    const key = path.split('/')[2]
    if (!key) {
      return res.status(400).json({ error: 'Key required' })
    }

    const now = Math.floor(Date.now() / 1000)
    const result = await sql`
      SELECT key, created_at, expires_at, active FROM api_keys WHERE key = ${key}
    `

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Key not found' })
    }

    const row = result.rows[0]
    const valid = row.active && row.expires_at > now
    return res.json({
      key: row.key,
      created_at: row.created_at,
      expires_at: row.expires_at,
      active: row.active,
      valid
    })
  }

  res.status(404).json({ error: 'Not found' })
}