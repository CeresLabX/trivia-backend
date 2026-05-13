require('dotenv').config();
const express = require('express');
const http = require('http');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { WebSocketServer } = require('ws');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// ── Database ────────────────────────────────────────────────────────────────
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ── Middleware ──────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static('/app'));  // serve trivia frontend

// ── Auth Middleware ─────────────────────────────────────────────────────────
function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = auth.slice(7);
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Auth Routes ─────────────────────────────────────────────────────────────

app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, display_name } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO trivia.users (username, email, password_hash, display_name)
       VALUES ($1, $2, $3, $4) RETURNING id, username, email, display_name`,
      [username, email, hash, display_name || username]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user });
  } catch (err) {
    if (err.code === '23505') {
      res.status(409).json({ error: 'Username or email already exists' });
    } else {
      console.error(err);
      res.status(500).json({ error: 'Registration failed' });
    }
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password' });
  }
  try {
    const result = await pool.query(
      `SELECT id, username, email, password_hash, display_name FROM trivia.users WHERE username = $1`,
      [username]
    );
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    await pool.query(`UPDATE trivia.users SET last_login = NOW() WHERE id = $1`, [user.id]);
    delete user.password_hash;
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, email, display_name, created_at FROM trivia.users WHERE id = $1`,
      [req.user.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// ── Questions API ─────────────────────────────────────────────────────────────

// Get all questions for a game (with optional difficulty filter)
app.get('/api/questions/:game', async (req, res) => {
  const { game } = req.params;
  const { difficulty } = req.query;
  try {
    let query = `SELECT id, difficulty, question, options, correct_index, source FROM trivia.questions WHERE game = $1`;
    const params = [game];
    if (difficulty) {
      query += ` AND difficulty = $2`;
      params.push(parseInt(difficulty));
    }
    query += ` ORDER BY difficulty, id`;
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch questions' });
  }
});

// Get one random question for a game (for single-player mode)
app.get('/api/question/:game/random', async (req, res) => {
  const { game } = req.params;
  const { difficulty } = req.query;
  try {
    let query = `SELECT id, difficulty, question, options, correct_index, source FROM trivia.questions WHERE game = $1`;
    const params = [game];
    if (difficulty) {
      query += ` AND difficulty = $2`;
      params.push(parseInt(difficulty));
    }
    query += ` ORDER BY RANDOM() LIMIT 1`;
    const result = await pool.query(query, params);
    if (!result.rows[0]) return res.status(404).json({ error: 'No questions found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch question' });
  }
});

// ── Score Routes ────────────────────────────────────────────────────────────

app.post('/api/scores', authenticate, async (req, res) => {
  const { game, score, questions_answered, correct_answers } = req.body;
  if (!game || score == null) {
    return res.status(400).json({ error: 'Missing game or score' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO trivia.scores (user_id, game, score, questions_answered, correct_answers)
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [req.user.id, game, score, questions_answered || 0, correct_answers || 0]
    );

    // Get rank
    const rankResult = await pool.query(
      `SELECT COUNT(*) + 1 as rank FROM trivia.scores
       WHERE game = $1 AND score > (SELECT score FROM trivia.scores WHERE id = $2)`,
      [game, result.rows[0].id]
    );
    res.json({ id: result.rows[0].id, rank: parseInt(rankResult.rows[0].rank) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save score' });
  }
});

app.get('/api/scores/:game/leaderboard', async (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  try {
    const result = await pool.query(
      `SELECT u.username, u.display_name, MAX(s.score) as best_score,
              COUNT(s.id) as games_played, MAX(s.played_at) as last_played
       FROM trivia.scores s
       JOIN trivia.users u ON u.id = s.user_id
       WHERE s.game = $1
       GROUP BY u.id, u.username, u.display_name
       ORDER BY best_score DESC, last_played ASC
       LIMIT $2`,
      [req.params.game, limit]
    );
    const leaderboard = result.rows.map((row, i) => ({
      rank: i + 1,
      username: row.username,
      display_name: row.display_name,
      best_score: row.best_score,
      games_played: parseInt(row.games_played),
      last_played: row.last_played
    }));
    res.json(leaderboard);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch leaderboard' });
  }
});

app.get('/api/scores/:game/:username', async (req, res) => {
  try {
    const userResult = await pool.query(`SELECT id FROM trivia.users WHERE username = $1`, [req.params.username]);
    if (!userResult.rows[0]) return res.status(404).json({ error: 'User not found' });
    const scores = await pool.query(
      `SELECT score, questions_answered, correct_answers, played_at
       FROM trivia.scores WHERE user_id = $1 AND game = $2
       ORDER BY played_at DESC LIMIT 20`,
      [userResult.rows[0].id, req.params.game]
    );
    res.json(scores.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch scores' });
  }
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// ── WebSocket Multiplayer ────────────────────────────────────────────────────
const wss = new WebSocketServer({ server, path: '/play' });

// Matchmaking queues per game
const queues = {};
// Active games: gameId -> { players: [{ws, user, score, answered, answer_time}], questions, current_round, total_rounds }
const activeGames = {};

function broadcast(gameId, data) {
  const game = activeGames[gameId];
  if (!game) return;
  const msg = JSON.stringify(data);
  game.players.forEach(p => {
    if (p.ws.readyState === 1) p.ws.send(msg);
  });
}

function generateGameId() {
  return Math.random().toString(36).substring(2, 8).toUpperCase();
}

wss.on('connection', (ws, req) => {
  let token, user, game = null;
  
  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {
      case 'auth': {
        try {
          user = jwt.verify(msg.token, process.env.JWT_SECRET);
          ws.send(JSON.stringify({ type: 'auth_ok', user }));
        } catch {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' }));
        }
        break;
      }

      case 'find_match': {
        if (!user) return ws.send(JSON.stringify({ type: 'error', message: 'Not authenticated' }));
        const g = msg.game || 'trek';
        if (!queues[g]) queues[g] = [];
        // Check if someone else waiting
        const waiting = queues[g].findIndex(p => p.ws !== ws && p.ws.readyState === 1);
        if (waiting >= 0) {
          const opponent = queues[g].splice(waiting, 1)[0];
          startGame(g, [opponent, { ws, user }]);
        } else {
          queues[g].push({ ws, user });
          ws.send(JSON.stringify({ type: 'match_waiting', position: queues[g].length }));
        }
        break;
      }

      case 'cancel_match': {
        const g = msg.game || 'trek';
        const idx = queues[g]?.findIndex(p => p.ws === ws);
        if (idx >= 0) queues[g].splice(idx, 1);
        break;
      }

      case 'answer': {
        if (!game || !user) return;
        const player = game.players.find(p => p.user.id === user.id);
        if (!player || player.answered) return;
        player.answered = true;
        player.answer_index = msg.answer_index;
        player.answer_time = msg.time_ms || 0;
        
        // Notify opponent that someone answered
        const opponent = game.players.find(p => p.user.id !== user.id);
        if (opponent && opponent.ws.readyState === 1) {
          opponent.ws.send(JSON.stringify({ type: 'opponent_answered' }));
        }
        
        // Check if both answered
        if (game.players.every(p => p.answered)) {
          processRound(game);
        }
        break;
      }

      case 'leave_game': {
        if (game) {
          const opponent = game.players.find(p => p.ws !== ws);
          if (opponent && opponent.ws.readyState === 1) {
            opponent.ws.send(JSON.stringify({ type: 'opponent_disconnected' }));
          }
          delete activeGames[game.id];
          game = null;
        }
        break;
      }
    }
  });

  ws.on('close', () => {
    // Remove from queue
    for (const g of Object.keys(queues)) {
      queues[g] = queues[g].filter(p => p.ws !== ws);
    }
    // Remove from game
    if (game) {
      const opponent = game.players.find(p => p.ws !== ws);
      if (opponent && opponent.ws.readyState === 1) {
        opponent.ws.send(JSON.stringify({ type: 'opponent_disconnected' }));
      }
      delete activeGames[game.id];
    }
  });
});

async function startGame(gameName, players) {
  const gameId = generateGameId();
  const game = {
    id: gameId,
    game: gameName,
    players: players.map(p => ({ ...p, score: 0, answered: false, answer_index: null, answer_time: null })),
    current_round: 0,
    total_rounds: 10,
    questions: [],  // loaded from DB
    round_active: false
  };
  activeGames[gameId] = game;

  // Load questions from database
  try {
    const result = await pool.query(
      `SELECT question, options, correct_index FROM trivia.questions WHERE game = $1 ORDER BY RANDOM() LIMIT $2`,
      [gameName, game.total_rounds]
    );
    if (result.rows.length > 0) {
      game.questions = result.rows.map(row => ({
        q: row.question,
        options: row.options,  // already a JSON array from DB
        a: row.correct_index
      }));
    }
  } catch (err) {
    console.error('Error loading questions from DB:', err);
  }

  // Fallback if no questions in DB
  if (game.questions.length === 0) {
    game.questions = Array(game.total_rounds).fill({
      q: 'Sample question?',
      options: ['A', 'B', 'C', 'D'],
      a: 0
    });
  }

  // Notify both players
  players.forEach(p => {
    const opponent = players.find(op => op.ws !== p.ws);
    p.ws.send(JSON.stringify({
      type: 'match_found',
      game_id: gameId,
      opponent: { username: opponent.user.username, display_name: opponent.user.display_name || opponent.user.username },
      total_rounds: game.total_rounds
    }));
  });

  // Start first round after 2 seconds
  setTimeout(() => sendRound(game), 2000);
}

function sendRound(game) {
  game.current_round++;
  game.players.forEach(p => { p.answered = false; p.answer_index = null; p.answer_time = null; });
  
  const q = game.questions[game.current_round - 1];
  const payload = {
    type: 'question',
    round: game.current_round,
    question: q.q,
    options: q.options,
    time_limit_ms: 20000
  };
  
  game.players.forEach(p => {
    if (p.ws.readyState === 1) p.ws.send(JSON.stringify(payload));
  });
}

function processRound(game) {
  const q = game.questions[game.current_round - 1];
  const correct = q.a;

  const results = game.players.map(p => {
    const is_correct = p.answer_index === correct;
    // Base points
    let points = 0;
    if (is_correct) {
      const base = 1000;
      const time_bonus = Math.max(0, 1000 - (p.answer_time || 20000));
      points = base + Math.floor(time_bonus / 2);
      p.score += points;
    }
    return { username: p.user.username, answer: p.answer_index, correct: is_correct, points, your_score: p.score };
  });

  const broadcast_data = {
    type: 'round_result',
    round: game.current_round,
    correct_answer: correct,
    results
  };
  broadcast(game.id, broadcast_data);

  if (game.current_round >= game.total_rounds) {
    setTimeout(() => endGame(game), 3000);
  } else {
    setTimeout(() => sendRound(game), 4000);
  }
}

function endGame(game) {
  const sorted = [...game.players].sort((a, b) => b.score - a.score);
  const winner = sorted[0].user.id;
  const loser = sorted[1]?.user.id || null;

  broadcast(game.id, {
    type: 'game_over',
    final_scores: game.players.map(p => ({ username: p.user.username, score: p.score })),
    winner_id: winner,
    your_score: game.players[0]?.score || 0,
    opponent_score: game.players[1]?.score || 0
  });

  // Save scores to DB (async, don't block)
  game.players.forEach(async p => {
    try {
      await pool.query(
        `INSERT INTO trivia.scores (user_id, game, score, questions_answered, correct_answers)
         VALUES ($1, $2, $3, $4, $5)`,
        [p.user.id, game.game, p.score, game.total_rounds, Math.round(game.total_rounds / 2)]
      );
    } catch (e) { console.error('Score save error:', e); }
  });

  delete activeGames[game.id];
}

// ── Start ────────────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Trivia Vault server running on port ${PORT}`);
});
