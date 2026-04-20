import discord
from discord.ext import commands
import json
import time
import os
from dotenv import load_dotenv

# =========================
# ENV LOAD
# =========================
load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")

SAFE_MODE_DEFAULT = os.getenv("SAFE_MODE", "true").lower() == "true"
GLOBAL_THRESHOLD_DEFAULT = float(os.getenv("GLOBAL_THRESHOLD", 60))

if TOKEN is None:
    raise Exception("❌ DISCORD_TOKEN no encontrado en .env")

# =========================
# DISCORD SETUP
# =========================
intents = discord.Intents.all()
bot = commands.Bot(command_prefix="!", intents=intents)

DB_FILE = "guardian_release.json"

# =========================
# DB
# =========================
def load():
    if not os.path.exists(DB_FILE):
        return {
            "users": {},
            "guilds": {},
            "settings": {
                "safe_mode": SAFE_MODE_DEFAULT,
                "global_threshold": GLOBAL_THRESHOLD_DEFAULT
            }
        }
    with open(DB_FILE, "r") as f:
        return json.load(f)

db = load()

def save():
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

def now():
    return time.time()

# =========================
# GUILD SYSTEM
# =========================
def g(gid):
    gid = str(gid)
    if gid not in db["guilds"]:
        db["guilds"][gid] = {
            "risk": 0,
            "quarantine": False,
            "threshold": db["settings"]["global_threshold"],
            "safe_mode": db["settings"]["safe_mode"]
        }
    return db["guilds"][gid]

def user(uid):
    uid = str(uid)
    if uid not in db["users"]:
        db["users"][uid] = {
            "reputation": 100,
            "warnings": 0,
            "fingerprint": [0, 0, 0, 0, 0],
            "last_seen": now()
        }
    return db["users"][uid]

# =========================
# FINGERPRINT ENGINE
# =========================
def update_fp(fp, event):
    if event == "msg":
        fp[0] += 1
    elif event == "mention":
        fp[1] += 1
    elif event == "join":
        fp[2] += 1
    fp[3] += 1
    return fp

def calculate_risk(fp):
    return (fp[0] * 0.5) + (fp[1] * 2) + (fp[3] * 0.3)

# =========================
# MESSAGE SYSTEM
# =========================
@bot.event
async def on_message(message):
    if not message.guild or message.author.bot:
        return

    u = user(message.author.id)
    gcfg = g(message.guild.id)

    fp = u["fingerprint"]

    if message.mention_everyone:
        update_fp(fp, "mention")
        u["warnings"] += 1
        u["reputation"] -= 3
    else:
        update_fp(fp, "msg")

    risk = calculate_risk(fp)

    # 🧠 RISK CONTROL
    if risk > gcfg["threshold"]:
        u["reputation"] -= 5
        u["warnings"] += 1

    # 🚫 KICK LOW REPUTATION
    if u["reputation"] <= 50:
        try:
            await message.author.kick(reason="Guardian AI reputation system")
        except:
            pass

    gcfg["risk"] = risk

    # 🧱 QUARANTINE MODE
    if risk > gcfg["threshold"]:
        gcfg["quarantine"] = True

    save()

    await bot.process_commands(message)

# =========================
# JOIN PROTECTION
# =========================
@bot.event
async def on_member_join(member):
    gcfg = g(member.guild.id)
    u = user(member.id)

    update_fp(u["fingerprint"], "join")

    if gcfg["quarantine"]:
        try:
            await member.kick(reason="Quarantine mode active")
        except:
            pass

    save()

# =========================
# PREFIX COMMANDS (!)
# =========================
@bot.command()
async def status(ctx):
    gcfg = g(ctx.guild.id)

    await ctx.send(
        f"""🛡️ GUARDIAN AI STATUS

📊 Risk: {gcfg['risk']}
🧱 Quarantine: {gcfg['quarantine']}
⚙️ Safe Mode: {gcfg['safe_mode']}
📉 Threshold: {gcfg['threshold']}"""
    )

@bot.command()
async def risk(ctx):
    gcfg = g(ctx.guild.id)
    await ctx.send(f"📊 Risk actual: {gcfg['risk']}")

# =========================
# SLASH CONFIG
# =========================
@bot.tree.command(name="config")
async def config(interaction: discord.Interaction, option: str, value: str = None):

    gcfg = g(interaction.guild.id)

    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Sin permisos", ephemeral=True)
        return

    if option == "safe_mode":
        gcfg["safe_mode"] = not gcfg["safe_mode"]
        await interaction.response.send_message(f"⚙️ Safe mode: {gcfg['safe_mode']}")

    elif option == "reset":
        gcfg["risk"] = 0
        gcfg["quarantine"] = False
        await interaction.response.send_message("🔄 Sistema reseteado")

    elif option == "threshold":
        try:
            gcfg["threshold"] = float(value)
            await interaction.response.send_message(f"📊 Threshold: {value}")
        except:
            await interaction.response.send_message("❌ Valor inválido")

    elif option == "view":
        await interaction.response.send_message(
            f"""⚙️ CONFIG

Safe Mode: {gcfg['safe_mode']}
Threshold: {gcfg['threshold']}
Quarantine: {gcfg['quarantine']}
Risk: {gcfg['risk']}"""
        )

    save()

# =========================
# HELP INTERACTIVO UI
# =========================
HELP = {}

HELP["home"] = discord.Embed(
    title="🛡️ Guardian AI Control Panel",
    description="Sistema anti-raid inteligente interactivo",
    color=0x00ffcc
)

HELP["home"].add_field(
    name="📚 Secciones",
    value="🧠 AI | ⚙️ Config | 🛡️ Security | 📊 Stats",
    inline=False
)

HELP["ai"] = discord.Embed(title="🧠 AI System", description="Fingerprint + risk engine", color=0x3498db)
HELP["config"] = discord.Embed(title="⚙️ Config", description="Slash /config control panel", color=0xf1c40f)
HELP["security"] = discord.Embed(title="🛡️ Security", description="Anti-raid + quarantine system", color=0xe74c3c)
HELP["stats"] = discord.Embed(title="📊 Stats", description="Server monitoring", color=0x9b59b6)

class HelpView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=60)

    @discord.ui.button(label="🏠 Home", style=discord.ButtonStyle.blurple)
    async def home(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(embed=HELP["home"], view=self)

    @discord.ui.button(label="🧠 AI", style=discord.ButtonStyle.gray)
    async def ai(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(embed=HELP["ai"], view=self)

    @discord.ui.button(label="⚙️ Config", style=discord.ButtonStyle.green)
    async def config(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(embed=HELP["config"], view=self)

    @discord.ui.button(label="🛡️ Security", style=discord.ButtonStyle.red)
    async def security(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(embed=HELP["security"], view=self)

    @discord.ui.button(label="📊 Stats", style=discord.ButtonStyle.secondary)
    async def stats(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(embed=HELP["stats"], view=self)

@bot.command()
async def ghelp(ctx):
    await ctx.send(embed=HELP["home"], view=HelpView())

# =========================
# READY
# =========================
@bot.event
async def on_ready():
    await bot.tree.sync()
    print(f"🛡️ Guardian AI FINAL activo como {bot.user}")

# =========================
# RUN
# =========================
bot.run(TOKEN)
