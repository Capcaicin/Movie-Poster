const express = require("express");
const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------------------
// Config from environment
// ---------------------------------------------------------------------------
function loadEnv() {
  const envPath = path.join(__dirname, ".env");
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const idx = trimmed.indexOf("=");
    if (idx === -1) continue;
    const key = trimmed.slice(0, idx).trim();
    const val = trimmed.slice(idx + 1).trim();
    if (!process.env[key]) process.env[key] = val;
  }
}
loadEnv();

const TRAKT_CLIENT_ID = process.env.TRAKT_CLIENT_ID;
const TRAKT_CLIENT_SECRET = process.env.TRAKT_CLIENT_SECRET;
const TMDB_API_KEY = process.env.TMDB_API_KEY;
const TRAKT_USERNAME = process.env.TRAKT_USERNAME || "me";
const PORT = parseInt(process.env.PORT || "3000", 10);

const TOKEN_PATH = path.join(__dirname, "token-store.json");

// ---------------------------------------------------------------------------
// Token persistence
// ---------------------------------------------------------------------------
function loadTokens() {
  try {
    return JSON.parse(fs.readFileSync(TOKEN_PATH, "utf8"));
  } catch {
    return null;
  }
}

function saveTokens(tokens) {
  fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2));
}

let tokens = loadTokens();

// ---------------------------------------------------------------------------
// Trakt helpers
// ---------------------------------------------------------------------------
async function traktFetch(urlPath, options = {}) {
  const url = `https://api.trakt.tv${urlPath}`;
  const headers = {
    "Content-Type": "application/json",
    "trakt-api-version": "2",
    "trakt-api-key": TRAKT_CLIENT_ID,
    ...options.headers,
  };
  if (tokens?.access_token) {
    headers["Authorization"] = `Bearer ${tokens.access_token}`;
  }
  const res = await fetch(url, { ...options, headers });
  return res;
}

async function refreshAccessToken() {
  if (!tokens?.refresh_token) return false;
  try {
    const res = await fetch("https://api.trakt.tv/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        refresh_token: tokens.refresh_token,
        client_id: TRAKT_CLIENT_ID,
        client_secret: TRAKT_CLIENT_SECRET,
        redirect_uri: "urn:ietf:wg:oauth:2.0:oob",
        grant_type: "refresh_token",
      }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    tokens = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: Date.now() + data.expires_in * 1000,
    };
    saveTokens(tokens);
    console.log("[auth] Token refreshed successfully");
    return true;
  } catch (err) {
    console.error("[auth] Token refresh failed:", err.message);
    return false;
  }
}

function isTokenExpired() {
  if (!tokens?.expires_at) return true;
  return Date.now() > tokens.expires_at - 300_000; // 5 min buffer
}

// ---------------------------------------------------------------------------
// TMDB helper
// ---------------------------------------------------------------------------
async function tmdbFetch(urlPath) {
  const url = `https://api.themoviedb.org/3${urlPath}`;
  const separator = urlPath.includes("?") ? "&" : "?";
  const res = await fetch(`${url}${separator}api_key=${TMDB_API_KEY}`);
  if (!res.ok) return null;
  return res.json();
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ---- Auth status ---------------------------------------------------------
app.get("/auth/status", (req, res) => {
  res.json({
    authenticated: !!tokens?.access_token,
    username: TRAKT_USERNAME,
    expires_at: tokens?.expires_at || null,
  });
});

// ---- Device code flow: step 1 - get code ---------------------------------
let pendingDevice = null;

app.post("/auth/device", async (req, res) => {
  try {
    const traktRes = await fetch("https://api.trakt.tv/oauth/device/code", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: TRAKT_CLIENT_ID }),
    });
    if (!traktRes.ok) {
      return res.status(502).json({ error: "Failed to get device code" });
    }
    const data = await traktRes.json();
    pendingDevice = {
      device_code: data.device_code,
      interval: data.interval || 5,
      expires_at: Date.now() + data.expires_in * 1000,
    };
    res.json({
      user_code: data.user_code,
      verification_url: data.verification_url,
      expires_in: data.expires_in,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- Device code flow: step 2 - poll for token ---------------------------
app.post("/auth/poll", async (req, res) => {
  if (!pendingDevice) {
    return res.status(400).json({ error: "No pending device auth. Call POST /auth/device first." });
  }
  if (Date.now() > pendingDevice.expires_at) {
    pendingDevice = null;
    return res.status(410).json({ error: "Device code expired. Start over." });
  }
  try {
    const traktRes = await fetch("https://api.trakt.tv/oauth/device/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: pendingDevice.device_code,
        client_id: TRAKT_CLIENT_ID,
        client_secret: TRAKT_CLIENT_SECRET,
      }),
    });

    if (traktRes.status === 400) {
      // User hasn't authorized yet — keep polling
      return res.json({ status: "pending", interval: pendingDevice.interval });
    }
    if (traktRes.status === 409) {
      return res.json({ status: "already_approved" });
    }
    if (traktRes.status === 418) {
      pendingDevice = null;
      return res.status(403).json({ status: "denied" });
    }
    if (traktRes.status === 410) {
      pendingDevice = null;
      return res.status(410).json({ status: "expired" });
    }
    if (traktRes.status === 429) {
      return res.json({ status: "slow_down", interval: pendingDevice.interval + 1 });
    }
    if (!traktRes.ok) {
      return res.status(502).json({ error: `Trakt returned ${traktRes.status}` });
    }

    const data = await traktRes.json();
    tokens = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: Date.now() + data.expires_in * 1000,
    };
    saveTokens(tokens);
    pendingDevice = null;
    console.log("[auth] Device authorized successfully");
    res.json({ status: "authorized" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- Now Playing proxy + TMDB enrichment ---------------------------------
app.get("/api/now-playing", async (req, res) => {
  try {
    // Refresh token if needed
    if (tokens && isTokenExpired()) {
      await refreshAccessToken();
    }

    const username = tokens?.access_token ? "me" : TRAKT_USERNAME;
    const traktRes = await traktFetch(`/users/${username}/watching`);

    // 204 = nothing playing
    if (traktRes.status === 204 || traktRes.status === 404) {
      return res.json({ playing: false });
    }
    if (!traktRes.ok) {
      return res.status(502).json({ error: `Trakt returned ${traktRes.status}` });
    }

    const data = await traktRes.json();
    if (!data || !data.type) {
      return res.json({ playing: false });
    }

    const mediaType = data.type; // "movie" or "episode"
    const item = data[mediaType];
    const tmdbId = item?.ids?.tmdb;

    // Base response from Trakt
    const result = {
      playing: true,
      type: mediaType,
      title: item.title,
      year: item.year,
      trakt: item,
    };

    // Episode-specific: include show info
    if (mediaType === "episode" && data.show) {
      result.show = data.show;
      result.title = data.show.title;
      result.year = data.show.year;
      result.episode_title = item.title;
      result.season = item.season;
      result.episode = item.number;
    }

    // Enrich with TMDB
    if (tmdbId) {
      const tmdbType = mediaType === "episode" ? "tv" : "movie";
      const tmdbData = await tmdbFetch(
        `/${tmdbType}/${mediaType === "episode" ? data.show.ids.tmdb : tmdbId}?append_to_response=credits,images`
      );
      if (tmdbData) {
        result.poster = tmdbData.poster_path
          ? `https://image.tmdb.org/t/p/original${tmdbData.poster_path}`
          : null;
        result.backdrop = tmdbData.backdrop_path
          ? `https://image.tmdb.org/t/p/original${tmdbData.backdrop_path}`
          : null;
        result.overview = tmdbData.overview || item.overview || "";
        result.rating = tmdbData.vote_average || 0;
        result.cast = (tmdbData.credits?.cast || []).slice(0, 8).map((a) => ({
          name: a.name,
          character: a.character,
          photo: a.profile_path
            ? `https://image.tmdb.org/t/p/w185${a.profile_path}`
            : null,
        }));

        // For episodes, also fetch episode-specific still image
        if (mediaType === "episode") {
          const epData = await tmdbFetch(
            `/tv/${data.show.ids.tmdb}/season/${item.season}/episode/${item.number}`
          );
          if (epData?.still_path) {
            result.episode_still = `https://image.tmdb.org/t/p/original${epData.still_path}`;
          }
          if (epData?.overview) {
            result.episode_overview = epData.overview;
          }
        }
      }
    }

    res.json(result);
  } catch (err) {
    console.error("[now-playing]", err);
    res.status(500).json({ error: err.message });
  }
});

// ---- Start ---------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`[side-tv] Server running on http://localhost:${PORT}`);
  console.log(`[side-tv] Auth status: ${tokens ? "authenticated" : "not authenticated"}`);
  if (!TRAKT_CLIENT_ID) console.warn("[side-tv] WARNING: TRAKT_CLIENT_ID not set");
  if (!TMDB_API_KEY) console.warn("[side-tv] WARNING: TMDB_API_KEY not set");
});
