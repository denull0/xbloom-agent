# XBloom + Claude

Let Claude create custom coffee and tea recipes for your XBloom Studio machine. Just tell Claude about your coffee or tea — or snap a photo of the bag — and it designs a recipe that syncs straight to your xBloom app.

No coding needed. Works on Claude desktop, mobile, and web.

---

## Get Started

### Step 1: Connect to Claude

Open Claude and add this server URL in your integrations settings:

```
https://ramaokxdyszcqpqxmosv.supabase.co/functions/v1/xbloom-mcp
```

**Where to find it:**
- **Desktop app** — Settings > Integrations > Add
- **iPhone / Android** — Settings > Integrations > Add
- **claude.ai** — Profile > Settings > Integrations > Add

Approve the connection when prompted.

### Step 2: Sign in with your XBloom account

The first time you use it, Claude will ask for your XBloom email and password. This links your XBloom account so recipes go directly to **your** app. Your password is used once and **never saved**.

### Step 3: Start chatting

Ask Claude to make you a recipe. Here are some ideas:

**Coffee:**

> *"Here's a photo of my coffee bag. Make me a recipe for it."*

> *"I have a medium roast Colombian, 18g dose. I like it bright and clean."*

> *"That last brew was a little bitter — can you adjust?"*

**Tea:**

> *"Create a tea recipe for my hojicha, 5g, two steeps."*

> *"Make a green tea recipe — 3g sencha, 70°C, 60 second steep."*

> *"I want an oolong recipe with three steeps, getting hotter each time."*

**Manage:**

> *"Show me all my recipes."*

> *"Delete the old test recipe."*

Recipes sync instantly to the **xBloom iOS app** and are ready to brew.

### What can it do?

- **Coffee recipes** — Pour-over recipes for the Omni dripper using brewing science (Kasuya 4:6, Hoffmann, Rao, etc.)
- **Tea recipes** — Steep recipes for the Omni Tea Brewer with proper temperatures and steep times
- **Photo-to-recipe** — Take a photo of your coffee or tea bag, Claude reads the label and creates a recipe
- **Link-to-recipe** — Paste a product link, Claude pulls the details and designs a recipe
- **Taste adjustments** — Tell Claude it was too bitter/sour/weak and it tweaks the recipe
- **Manage recipes** — List, edit, and delete recipes right from the chat
- **Import recipes** — Grab any shared XBloom recipe by URL

### Privacy

- Your password is **never stored** — it's used once to log in, then thrown away
- Each user has their own account — nobody else can see or touch your recipes
- Session tokens are encrypted at rest

---

## Developer Guide

Everything below is for developers who want to self-host or modify the server.

### Tech Stack

- **Runtime**: Deno 2.x on Supabase Edge Functions
- **Protocol**: MCP 2.0 (Streamable HTTP + SSE)
- **Auth**: OAuth 2.0 + per-user XBloom login
- **Encryption**: AES-256-CBC (sessions) + RSA (API payloads, XBloom's key)

### MCP Tools

| Tool | Description |
|------|-------------|
| `xbloom_login` | Authenticate with your XBloom account |
| `xbloom_list_recipes` | List all your recipes with IDs |
| `xbloom_create_recipe` | Create a coffee recipe (Omni dripper) |
| `xbloom_create_tea_recipe` | Create a tea recipe (Omni Tea Brewer) |
| `xbloom_edit_recipe` | Update an existing recipe by ID |
| `xbloom_delete_recipe` | Permanently remove a recipe |
| `xbloom_fetch_recipe` | Import a recipe from a share URL |

### Self-Hosting

#### Prerequisites

- [Supabase CLI](https://supabase.com/docs/guides/cli/getting-started)
- [Deno 2.x](https://deno.com)

#### 1. Clone and deploy

```bash
git clone https://github.com/denull0/xbloom-agent.git
cd xbloom-agent/xbloom-mcp-remote
supabase functions deploy xbloom-mcp --no-verify-jwt
```

#### 2. Create the sessions table

```sql
CREATE TABLE user_sessions (
  access_token TEXT PRIMARY KEY,
  encrypted_creds TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
```

No environment variables needed — the server uses `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` which are automatically available in edge functions.

#### 3. Connect Claude

Add your server URL in Claude integrations:

```
https://<your-project>.supabase.co/functions/v1/xbloom-mcp
```

### Recipe Parameters

**Coffee** (Omni dripper):

| Parameter | Range | Notes |
|-----------|-------|-------|
| `dose_g` | 1–31 | Coffee dose in grams |
| `grind_size` | 40–120 | Lower = finer |
| `grind_rpm` | 60–120 | Grinder speed |
| `temperature_c` | 40–95 | Water temperature |
| `flow_rate` | 3.0–3.5 | mL/s |
| `pattern` | centered, circular, spiral | Pour pattern |
| `pause_seconds` | 0–255 | Pause between pours |

**Tea** (Omni Tea Brewer):

| Parameter | Range | Notes |
|-----------|-------|-------|
| `dose_g` | 1–10 | Tea dose in grams |
| `volume_ml` | 1–90 | Water per steep (machine adds ~30ml for siphon) |
| `temperature_c` | 65–100 | Green: 70-80, White: 75-85, Oolong: 85-95, Black: 90-100 |
| `steep_seconds` | 0–360 | Up to 6 minutes per steep |
| `steeps` | 1–3 | Number of steeps |

### Project Structure

```
xbloom-agent/
├── xbloom-mcp-remote/
│   └── supabase/
│       ├── config.toml                     # Supabase project config
│       └── functions/
│           └── xbloom-mcp/index.ts         # MCP server (OAuth + tools + SSE)
└── xbloom-recipes/
    └── claude-project/
        ├── custom-instructions.md          # Claude project instructions
        └── xbloom-brewing-reference.md     # Coffee brewing science reference
```

### Security

- Passwords are **never stored** — used once for XBloom API login, then discarded
- Session tokens are **AES-256 encrypted** at rest using HMAC-SHA256 derived keys
- Database table has **Row Level Security** — only the server can access it
- Error messages are sanitized — no internal API details leaked

## License

MIT
