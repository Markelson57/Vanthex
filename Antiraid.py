import asyncio
import copy
import io
import json
import logging
import os
import random
import re
import time
from collections import defaultdict, deque
from datetime import timedelta
from typing import Union

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands
from discord.ui import View
from dotenv import load_dotenv


load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
if not TOKEN:
    raise ValueError("DISCORD_TOKEN no configurado en .env")

DB_FILE = "guardian_db.json"
WINDOW = 10
RECENT_JOIN_CACHE = 100

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("guardian")


DEFAULT_GUILD_CONFIG = {
    "lockdown": False,
    "raid_mode": False,
    "whitelist": [],
    "blacklists": [],
    "bans_log": [],
    "verify_role": None,
    "slowmode_duration": 0,
    "antispam_level": 1,
    "raid_history": [],
    "user_stats": {},
    "channel_locks": {},
    "role_locks": {},
    "captcha_enabled": False,
    "threshold_joins": 5,
    "threshold_msgs": 8,
    "log_channel": None,
    "alert_channel": None,
    "webhook_logs": None,
    "ban_patterns": [],
    "link_filter": False,
    "mention_limit": 5,
    "emoji_limit": 5,
    "nitro_links": False,
    "invite_spam_limit": 3,
    "spam_incidents": 0,
    "warns": {},
    "strikes": {},
    "lockdown_mode": "soft",
}

INVITE_REGEX = re.compile(
    r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord(?:app)?\.com/invite)/[A-Za-z0-9-]+",
    re.IGNORECASE,
)
CUSTOM_EMOJI_REGEX = re.compile(r"<a?:\w+:\d+>")


intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.guilds = True

bot = commands.Bot(command_prefix="!", intents=intents)


def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r", encoding="utf-8") as file:
                data = json.load(file)
                if "guilds" not in data or not isinstance(data["guilds"], dict):
                    data["guilds"] = {}
                return data
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Error cargando DB: %s", exc)
    return {"guilds": {}}


def save_db(data):
    try:
        with open(DB_FILE, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2, ensure_ascii=False)
    except OSError as exc:
        logger.error("Error guardando DB: %s", exc)


db = load_db()


def get_guild_config(guild_id: int):
    gid = str(guild_id)
    if gid not in db["guilds"]:
        db["guilds"][gid] = copy.deepcopy(DEFAULT_GUILD_CONFIG)
        save_db(db)

    cfg = db["guilds"][gid]
    for key, value in DEFAULT_GUILD_CONFIG.items():
        cfg.setdefault(key, copy.deepcopy(value))
    return cfg


join_tracker = defaultdict(deque)
msg_tracker = defaultdict(lambda: defaultdict(deque))
recent_joins = defaultdict(lambda: deque(maxlen=RECENT_JOIN_CACHE))


def now_ts() -> float:
    return time.time()


def prune_deque(dq: deque, window: int):
    current = now_ts()
    while dq and current - dq[0] > window:
        dq.popleft()


def is_raid_join(guild_id: int) -> bool:
    joins = join_tracker[guild_id]
    prune_deque(joins, WINDOW)
    cfg = get_guild_config(guild_id)
    return len(joins) >= cfg["threshold_joins"]


def is_spam(guild_id: int, user_id: int) -> bool:
    msgs = msg_tracker[guild_id][user_id]
    prune_deque(msgs, WINDOW)
    cfg = get_guild_config(guild_id)
    return len(msgs) >= cfg["threshold_msgs"]


def member_is_whitelisted(member: discord.Member, cfg: dict) -> bool:
    return str(member.id) in cfg.get("whitelist", [])


def member_is_blacklisted(member: discord.Member, cfg: dict) -> bool:
    blacklisted = set(cfg.get("blacklists", []))
    if str(member.id) in blacklisted:
        return True
    return any(str(role.id) in blacklisted for role in member.roles)


def record_user_message(guild_id: int, user_id: int):
    cfg = get_guild_config(guild_id)
    user_stats = cfg.setdefault("user_stats", {})
    user_stats.setdefault(str(user_id), {"msgs": 0})
    user_stats[str(user_id)]["msgs"] += 1


def safe_member_name(member: discord.abc.User) -> str:
    return f"{member} ({member.id})"


def count_recent_joins(guild_id: int, seconds: int = 86400) -> int:
    current = now_ts()
    return sum(1 for entry in recent_joins[str(guild_id)] if current - entry["joined_at"] < seconds)


def count_member_recent_joins(guild_id: int, user_id: int) -> int:
    return sum(1 for entry in recent_joins[str(guild_id)] if entry["user_id"] == user_id)


def build_stats_embed(guild_id: int) -> discord.Embed:
    cfg = get_guild_config(guild_id)
    embed = discord.Embed(title="📊 Anti-Raid Stats", color=0xFF9900)
    embed.add_field(name="Lockdown", value=str(cfg["lockdown"]), inline=True)
    embed.add_field(name="Whitelist", value=str(len(cfg["whitelist"])), inline=True)
    embed.add_field(name="Spam Incidents", value=str(cfg["spam_incidents"]), inline=True)

    graph_fill = "█" * min(20, cfg["spam_incidents"] // 2)
    graph_empty = "░" * (20 - len(graph_fill))
    embed.add_field(name="Spam Graph", value=f"[{graph_fill}{graph_empty}]", inline=False)
    return embed


def get_bot_member(guild: discord.Guild):
    return guild.me or guild.get_member(bot.user.id if bot.user else 0)


def bot_has_perms(guild: discord.Guild, needed: list[str]) -> bool:
    bot_member = get_bot_member(guild)
    if not bot_member:
        return False
    permissions = bot_member.guild_permissions
    return all(getattr(permissions, name, False) for name in needed)


async def send_log(guild_id: int, message: str):
    cfg = get_guild_config(guild_id)
    channel_id = cfg.get("log_channel")
    if not channel_id:
        return

    channel = bot.get_channel(int(channel_id))
    if channel:
        try:
            await channel.send(message)
        except discord.DiscordException as exc:
            logger.warning("No se pudo enviar log en %s: %s", guild_id, exc)


async def send_alert(guild_id: int, message: str):
    cfg = get_guild_config(guild_id)
    channel_id = cfg.get("alert_channel")
    if not channel_id:
        return

    channel = bot.get_channel(int(channel_id))
    if channel:
        try:
            await channel.send(f"🚨 {message}")
        except discord.DiscordException as exc:
            logger.warning("No se pudo enviar alerta en %s: %s", guild_id, exc)


async def send_webhook(guild_id: int, message: str):
    cfg = get_guild_config(guild_id)
    webhook_url = cfg.get("webhook_logs")
    if not webhook_url:
        return

    try:
        async with aiohttp.ClientSession() as session:
            webhook = discord.Webhook.from_url(webhook_url, session=session)
            await webhook.send(message)
    except Exception as exc:
        logger.warning("No se pudo enviar webhook en %s: %s", guild_id, exc)


async def trigger_lockdown(guild: discord.Guild):
    cfg = get_guild_config(guild.id)
    if cfg["lockdown"]:
        return

    cfg["lockdown"] = True
    cfg["raid_history"].append(
        {
            "timestamp": now_ts(),
            "reason": "Raid detectado por uniones masivas",
            "mode": cfg.get("lockdown_mode", "soft"),
        }
    )
    save_db(db)

    await send_alert(guild.id, "🔒 LOCKDOWN ACTIVADO - RAID")
    await send_webhook(guild.id, "PANIC LOCKDOWN")

    lockdown_mode = cfg.get("lockdown_mode", "soft")
    if lockdown_mode != "hard":
        await send_log(guild.id, "PANIC MODE (SOFT) activado.")
        return

    if not bot_has_perms(guild, ["kick_members"]):
        await send_alert(guild.id, "No tengo permisos para expulsar miembros durante el lockdown hard.")
        return

    kicked = 0
    for member in guild.members:
        if member.bot or member_is_whitelisted(member, cfg):
            continue
        try:
            await member.kick(reason="PANIC Anti-Raid")
            kicked += 1
        except discord.DiscordException as exc:
            logger.warning("No se pudo expulsar a %s: %s", safe_member_name(member), exc)

    await send_log(guild.id, f"{kicked} miembros expulsados durante PANIC MODE (HARD)")


class Pagination(View):
    def __init__(self, pages: list[str], title: str = "Lista"):
        super().__init__(timeout=300)
        self.pages = pages or ["No hay contenido para mostrar."]
        self.title = title
        self.page = 0
        self.ctx = None
        self.embed = discord.Embed()
        self._refresh_embed()
        self._refresh_buttons()

    def _refresh_embed(self):
        self.embed = discord.Embed(
            title=self.title,
            description=self.pages[self.page],
            color=0x2F3136,
        )
        self.embed.set_footer(text=f"Pág {self.page + 1}/{len(self.pages)}")

    def _refresh_buttons(self):
        self.prev.disabled = self.page == 0
        self.next.disabled = self.page >= len(self.pages) - 1

    @discord.ui.button(label="◀️", style=discord.ButtonStyle.grey)
    async def prev(self, interaction: discord.Interaction, _button: discord.ui.Button):
        if self.page > 0:
            self.page -= 1
        self._refresh_embed()
        self._refresh_buttons()
        await interaction.response.edit_message(embed=self.embed, view=self)

    @discord.ui.button(label="▶️", style=discord.ButtonStyle.grey)
    async def next(self, interaction: discord.Interaction, _button: discord.ui.Button):
        if self.page < len(self.pages) - 1:
            self.page += 1
        self._refresh_embed()
        self._refresh_buttons()
        await interaction.response.edit_message(embed=self.embed, view=self)

    @discord.ui.button(label="Stop", style=discord.ButtonStyle.red)
    async def stop_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(embed=self.embed, view=self)
        self.stop()

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        return bool(self.ctx and interaction.user == self.ctx.author)


class Confirm(View):
    def __init__(self, callback):
        super().__init__(timeout=60)
        self.callback = callback

    @discord.ui.button(label="Sí", style=discord.ButtonStyle.green)
    async def yes(self, interaction: discord.Interaction, _button: discord.ui.Button):
        self.stop()
        await self.callback(interaction, True)

    @discord.ui.button(label="No", style=discord.ButtonStyle.red)
    async def no(self, interaction: discord.Interaction, _button: discord.ui.Button):
        self.stop()
        await self.callback(interaction, False)


@bot.event
async def on_ready():
    logger.info("🛡️ MEGA BOT online como %s", bot.user)
    try:
        synced = await bot.tree.sync()
        logger.info("Slash commands sincronizados: %s", len(synced))
    except discord.HTTPException as exc:
        logger.error("No se pudieron sincronizar slash commands: %s", exc)

    await bot.change_presence(
        activity=discord.Game(name="Guardian Mode"),
        status=discord.Status.online,
    )


@bot.event
async def on_member_join(member: discord.Member):
    guild_id = member.guild.id
    cfg = get_guild_config(guild_id)

    recent_joins[str(guild_id)].append({"user_id": member.id, "joined_at": now_ts()})
    join_tracker[guild_id].append(now_ts())

    if member_is_blacklisted(member, cfg):
        await send_log(guild_id, f"🚫 Usuario en blacklist detectado: {member.mention}. Expulsando.")
        try:
            await member.kick(reason="Usuario o rol en blacklist")
        except discord.DiscordException as exc:
            await send_alert(guild_id, f"No pude expulsar a {member.mention}: {exc}")
        return

    if member_is_whitelisted(member, cfg):
        await send_log(guild_id, f"✅ Usuario en whitelist unido: {member.mention}")
        return

    if cfg.get("verify_role"):
        role = member.guild.get_role(int(cfg["verify_role"]))
        if role:
            try:
                await member.add_roles(role, reason="Auto verify role")
            except discord.DiscordException as exc:
                logger.warning("No se pudo dar verify role a %s: %s", safe_member_name(member), exc)

    await send_log(guild_id, f"👤 Join: {member.mention} ({member.id})")

    if cfg.get("captcha_enabled", False):
        try:
            a, b = random.randint(1, 10), random.randint(1, 10)
            await member.send(
                f"Bienvenido. Para verificar que no eres un bot responde: {a} + {b} = ?"
            )

            def check(message: discord.Message):
                return (
                    message.author.id == member.id
                    and isinstance(message.channel, discord.DMChannel)
                    and message.content.isdigit()
                )

            reply = await bot.wait_for("message", check=check, timeout=300)
            if int(reply.content) != a + b:
                await member.send("Respuesta incorrecta. Serás expulsado.")
                await member.kick(reason="Captcha incorrecto")
                await send_log(guild_id, f"CAPTCHA FALLIDO: {member.mention}")
                return

            await member.send("Verificación completada correctamente.")
            await send_log(guild_id, f"CAPTCHA PASADO: {member.mention}")

        except asyncio.TimeoutError:
            try:
                await member.send("Tiempo agotado. Serás expulsado.")
            except discord.DiscordException:
                pass
            try:
                await member.kick(reason="Captcha timeout")
            except discord.DiscordException:
                pass
            await send_log(guild_id, f"CAPTCHA TIMEOUT: {member.mention}")
            return
        except discord.Forbidden:
            await send_log(guild_id, f"No pude abrir DM con {member.mention} para el captcha.")
        except discord.DiscordException as exc:
            logger.warning("Error en captcha para %s: %s", safe_member_name(member), exc)

    if is_raid_join(guild_id):
        await trigger_lockdown(member.guild)


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    guild = message.guild
    guild_id = guild.id
    cfg = get_guild_config(guild_id)
    content = message.content.lower()

    if isinstance(message.author, discord.Member):
        member = message.author
    else:
        await bot.process_commands(message)
        return

    if member_is_blacklisted(member, cfg):
        try:
            await message.delete()
            await send_log(guild_id, f"🗑️ Mensaje borrado de usuario/rol en blacklist: {member.mention}")
        except discord.DiscordException:
            pass
        return

    record_user_message(guild_id, member.id)
    msg_tracker[guild_id][member.id].append(now_ts())

    deleted = False

    async def delete_and_report(log_text: str, alert_text: str):
        nonlocal deleted
        if deleted:
            return
        try:
            await message.delete()
            deleted = True
            cfg["spam_incidents"] += 1
            await send_log(guild_id, log_text)
            await send_alert(guild_id, alert_text)
        except discord.DiscordException as exc:
            logger.warning("No se pudo borrar mensaje: %s", exc)

    if not member_is_whitelisted(member, cfg):
        if cfg.get("link_filter") and ("http://" in content or "https://" in content):
            await delete_and_report(
                f"🔗 Enlace eliminado de {member.mention} ({member.id})",
                f"Enlace eliminado de {member.mention}",
            )

        if len(message.mentions) > cfg.get("mention_limit", 5):
            await delete_and_report(
                f"📢 Mention spam de {member.mention} ({member.id})",
                f"Mention spam de {member.mention}",
            )

        if len(CUSTOM_EMOJI_REGEX.findall(message.content)) > cfg.get("emoji_limit", 5):
            await delete_and_report(
                f"😃 Emoji spam de {member.mention} ({member.id})",
                f"Emoji spam de {member.mention}",
            )

        if cfg.get("nitro_links") and "discord.gift/" in content:
            await delete_and_report(
                f"🎁 Nitro scam detectado en mensaje de {member.mention}",
                f"Nitro scam detectado en mensaje de {member.mention}",
            )

        invite_count = len(INVITE_REGEX.findall(message.content))
        if invite_count >= cfg.get("invite_spam_limit", 3):
            await delete_and_report(
                f"📨 Invite spam de {member.mention} ({invite_count} invitaciones)",
                f"Invite spam de {member.mention}",
            )

        for pattern in cfg.get("ban_patterns", []):
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                logger.warning("Regex inválida '%s': %s", pattern, exc)
                continue

            if regex.search(message.content):
                if bot_has_perms(guild, ["ban_members"]):
                    try:
                        await guild.ban(member, reason=f"Pattern ban: {pattern}")
                        cfg["spam_incidents"] += 1
                        cfg["bans_log"].append(
                            {
                                "user": str(member.id),
                                "time": now_ts(),
                                "reason": f"Pattern ban: {pattern}",
                            }
                        )
                        await send_log(guild_id, f"🚫 Pattern ban a {member.mention} por `{pattern}`")
                        await send_alert(guild_id, f"Pattern ban a {member.mention}")
                    except discord.DiscordException as exc:
                        await send_alert(guild_id, f"No se pudo banear a {member.mention}: {exc}")
                break

        if is_spam(guild_id, member.id):
            if bot_has_perms(guild, ["moderate_members"]):
                try:
                    await member.timeout(
                        discord.utils.utcnow() + timedelta(minutes=10),
                        reason="Spam detectado",
                    )
                    cfg["spam_incidents"] += 1
                    await send_log(guild_id, f"⏳ Timeout a {member.mention} por spam")
                    await send_alert(guild_id, f"Timeout a {member.mention} por spam")
                except discord.DiscordException as exc:
                    logger.warning("No se pudo hacer timeout a %s: %s", safe_member_name(member), exc)

    if cfg.get("lockdown") and not member.guild_permissions.administrator:
        try:
            await message.delete()
            deleted = True
        except discord.DiscordException:
            pass

    save_db(db)

    if not deleted:
        await bot.process_commands(message)


@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    cfg = get_guild_config(after.guild.id)
    locked_roles = set(cfg.get("role_locks", {}).keys())
    if not locked_roles:
        return

    added_roles = [role for role in after.roles if role not in before.roles]
    for role in added_roles:
        if str(role.id) not in locked_roles:
            continue

        try:
            await after.remove_roles(role, reason="Rol bloqueado por Guardian")
            await send_alert(
                after.guild.id,
                f"Se retiró el rol bloqueado {role.mention} a {after.mention}.",
            )
        except discord.DiscordException as exc:
            logger.warning("No se pudo retirar rol bloqueado: %s", exc)


@bot.event
async def on_command_error(ctx: commands.Context, error: commands.CommandError):
    if hasattr(ctx.command, "on_error"):
        return

    if isinstance(error, commands.CommandNotFound):
        await ctx.send("Comando no encontrado.")
    elif isinstance(error, commands.MissingPermissions):
        await ctx.send("No tienes permisos para usar este comando.")
    elif isinstance(error, commands.BadArgument):
        await ctx.send("Argumento inválido.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"Falta un argumento requerido: {error.param.name}")
    elif isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f"Este comando está en cooldown. Reintenta en {error.retry_after:.1f}s.")
    elif isinstance(error, commands.BotMissingPermissions):
        await ctx.send(
            "Al bot le faltan permisos: " + ", ".join(error.missing_permissions)
        )
    else:
        logger.exception("Error no controlado en comando %s", ctx.command, exc_info=error)
        await ctx.send("Ocurrió un error inesperado al ejecutar el comando.")


@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if interaction.response.is_done():
        sender = interaction.followup.send
    else:
        sender = interaction.response.send_message

    if isinstance(error, app_commands.MissingPermissions):
        await sender("No tienes permisos para usar este comando.", ephemeral=True)
    else:
        logger.exception("Error en slash command", exc_info=error)
        await sender("Ocurrió un error al ejecutar el comando.", ephemeral=True)


@bot.command(name="panicmode")
@commands.has_permissions(administrator=True)
async def panic_mode(ctx: commands.Context):
    await trigger_lockdown(ctx.guild)
    await ctx.send("🚨 PANIC MODE ACTIVATED - Full lockdown + webhooks")


@bot.command(name="saferole")
@commands.has_permissions(administrator=True)
async def safe_role(ctx: commands.Context):
    cfg = get_guild_config(ctx.guild.id)
    verify_role_id = cfg.get("verify_role")
    if not verify_role_id:
        await ctx.send("No hay rol de verificación configurado. Usa `!setverifyrole @rol`.")
        return

    role = ctx.guild.get_role(int(verify_role_id))
    if not role:
        await ctx.send("El rol configurado ya no existe.")
        return

    assigned = 0
    for member in ctx.guild.members:
        if member.bot or role in member.roles:
            continue
        try:
            await member.add_roles(role, reason="Safe role assign")
            assigned += 1
        except discord.DiscordException as exc:
            logger.warning("No se pudo asignar rol seguro a %s: %s", safe_member_name(member), exc)

    await ctx.send(f"{assigned} miembros recibieron el rol seguro.")


@bot.command(name="riskscore")
async def risk_score(ctx: commands.Context):
    cfg = get_guild_config(ctx.guild.id)
    total_members = max(ctx.guild.member_count or 0, 1)
    joins_24h = count_recent_joins(ctx.guild.id, 86400)
    bans_24h = sum(1 for entry in cfg.get("bans_log", []) if now_ts() - entry.get("time", 0) < 86400)

    risk_joins = (joins_24h / total_members) * 100 * 0.5
    risk_spam = min(cfg.get("spam_incidents", 0), 100) * 0.3
    risk_bans = min(bans_24h * 10, 100) * 0.2
    risk = min(risk_joins + risk_spam + risk_bans, 100)

    color = 0xFF0000 if risk > 75 else 0xFFA500 if risk > 30 else 0x00FF00
    embed = discord.Embed(
        title=f"{ctx.guild.name} Risk Score",
        description=f"{risk:.1f}%",
        color=color,
    )
    embed.add_field(name="Uniones recientes (24h)", value=str(joins_24h), inline=True)
    embed.add_field(name="Incidentes de spam", value=str(cfg.get("spam_incidents", 0)), inline=True)
    embed.add_field(name="Baneos recientes (24h)", value=str(bans_24h), inline=True)
    await ctx.send(embed=embed)


@bot.command(name="patternban")
@commands.has_permissions(administrator=True)
async def pattern_ban(ctx: commands.Context, *, pattern: str):
    cfg = get_guild_config(ctx.guild.id)
    try:
        re.compile(pattern)
    except re.error as exc:
        await ctx.send(f"Regex inválida: {exc}")
        return

    if pattern not in cfg["ban_patterns"]:
        cfg["ban_patterns"].append(pattern)
        save_db(db)
    await ctx.send(f"Patrón `{pattern}` añadido.")


@bot.command(name="linkfilter")
@commands.has_permissions(administrator=True)
async def toggle_link_filter(ctx: commands.Context):
    cfg = get_guild_config(ctx.guild.id)
    cfg["link_filter"] = not cfg.get("link_filter", False)
    save_db(db)
    await ctx.send(f"Filtro de enlaces: {'ACTIVADO' if cfg['link_filter'] else 'DESACTIVADO'}")


@bot.command(name="mentionspam")
@commands.has_permissions(administrator=True)
async def mention_limit(ctx: commands.Context, limit: int = 5):
    cfg = get_guild_config(ctx.guild.id)
    cfg["mention_limit"] = max(1, limit)
    save_db(db)
    await ctx.send(f"Límite de menciones: {cfg['mention_limit']}")


@bot.command(name="emojispam")
@commands.has_permissions(administrator=True)
async def emoji_limit(ctx: commands.Context, limit: int = 5):
    cfg = get_guild_config(ctx.guild.id)
    cfg["emoji_limit"] = max(1, limit)
    save_db(db)
    await ctx.send(f"Límite de emojis: {cfg['emoji_limit']}")


@bot.command(name="nitroprotect")
@commands.has_permissions(administrator=True)
async def nitro_protect(ctx: commands.Context):
    cfg = get_guild_config(ctx.guild.id)
    cfg["nitro_links"] = not cfg.get("nitro_links", False)
    save_db(db)
    await ctx.send(
        f"Protección contra enlaces Nitro scam: {'ACTIVADA' if cfg['nitro_links'] else 'DESACTIVADA'}"
    )


@bot.command(name="invitespam")
@commands.has_permissions(administrator=True)
async def invite_limit(ctx: commands.Context, limit: int = 3):
    cfg = get_guild_config(ctx.guild.id)
    cfg["invite_spam_limit"] = max(1, limit)
    save_db(db)
    await ctx.send(f"Límite de invitaciones por mensaje: {cfg['invite_spam_limit']}")


@bot.command(name="guardianhelp")
async def anti_raid_help(ctx: commands.Context):
    commands_list = [
        "!panicmode",
        "!saferole",
        "!riskscore",
        "!patternban <regex>",
        "!linkfilter",
        "!mentionspam <límite>",
        "!emojispam <límite>",
        "!nitroprotect",
        "!invitespam <límite>",
        "!guardianhelp",
        "!dashboard",
        "!setverifyrole @rol",
        "!blacklist <@miembro|@rol>",
        "!banwave @rol",
        "!softban @miembro",
        "!usertrack [@miembro]",
        "!raidstats",
        "!top_spammers",
        "!recent_joins",
        "!lockchannel #canal",
        "!unlockchannel #canal",
        "!rolelock @rol",
        "!unlockrole @rol",
        "!captcha",
        "!vpncheck @miembro",
        "!masskick",
        "!configdump",
        "!config <clave> <valor>",
        "!resetdb",
        "!backupdb",
        "!webhooklogs <url>",
        "!alerttest",
        "!lockdownmode <soft|hard>",
        "!whitelistrole @rol",
        "!blacklistrole @rol",
        "!mutewave <minutos>",
        "!unmuteall",
        "!kickrecent <n>",
        "!banspammer @miembro",
        "!warns [@miembro]",
        "!strikes [@miembro]",
        "!forgive @miembro",
        "!auditlog",
        "!membercount",
        "!botperms",
        "!sync",
    ]
    pages = ["\n".join(commands_list[i : i + 10]) for i in range(0, len(commands_list), 10)]
    view = Pagination(pages, "Guardian Help")
    view.ctx = ctx
    await ctx.send(embed=view.embed, view=view)


@bot.command(name="dashboard")
async def dashboard(ctx: commands.Context):
    cfg = get_guild_config(ctx.guild.id)
    embed = discord.Embed(
        title="Dashboard",
        description="Resumen rápido del estado del sistema anti-raid.",
        color=0x00FFFF,
    )
    embed.add_field(name="Lockdown", value="ON" if cfg["lockdown"] else "OFF", inline=True)
    embed.add_field(name="Captcha", value="ON" if cfg["captcha_enabled"] else "OFF", inline=True)
    embed.add_field(name="Spam incidents", value=str(cfg["spam_incidents"]), inline=True)
    await ctx.send(embed=embed)


@bot.command(name="setverifyrole")
@commands.has_permissions(administrator=True)
async def set_verify_role(ctx: commands.Context, role: discord.Role):
    cfg = get_guild_config(ctx.guild.id)
    cfg["verify_role"] = str(role.id)
    save_db(db)
    await ctx.send(f"Rol de verificación configurado: {role.mention}")


@bot.command(name="blacklist")
@commands.has_permissions(administrator=True)
async def blacklist_add(ctx: commands.Context, target: Union[discord.Member, discord.Role]):
    cfg = get_guild_config(ctx.guild.id)
    cfg.setdefault("blacklists", [])

    if not isinstance(target, (discord.Member, discord.Role)):
        await ctx.send("Debes indicar un miembro o un rol.")
        return

    target_id = str(target.id)
    if target_id in cfg["blacklists"]:
        await ctx.send("Ese objetivo ya está en la blacklist.")
        return

    cfg["blacklists"].append(target_id)
    save_db(db)
    await ctx.send(f"{target.mention} añadido a la blacklist.")
@bot.command(name="banwave")
@commands.has_permissions(administrator=True)
async def ban_wave(ctx: commands.Context, role: discord.Role):
    async def confirm_callback(interaction: discord.Interaction, confirmed: bool):
        if not confirmed:
            await interaction.response.send_message("Acción cancelada.", ephemeral=True)
            return

        cfg = get_guild_config(ctx.guild.id)
        banned_count = 0
        for member in role.members:
            if member.id == bot.user.id or member_is_whitelisted(member, cfg):
                continue
            try:
                await ctx.guild.ban(member, reason="Banwave anti-raid")
                cfg["bans_log"].append(
                    {"user": str(member.id), "time": now_ts(), "reason": "Banwave"}
                )
                banned_count += 1
            except discord.DiscordException as exc:
                logger.warning("Banwave falló con %s: %s", safe_member_name(member), exc)

        save_db(db)
        await interaction.response.send_message(
            f"{banned_count} miembros del rol {role.mention} fueron baneados."
        )

    embed = discord.Embed(
        title="Confirmar Banwave",
        description=f"¿Seguro que quieres banear a {len(role.members)} miembros de {role.mention}?",
        color=0xFF0000,
    )
    await ctx.send(embed=embed, view=Confirm(confirm_callback))


@bot.command(name="softban")
@commands.has_permissions(administrator=True)
async def soft_ban(ctx: commands.Context, member: discord.Member):
    cfg = get_guild_config(ctx.guild.id)
    if member.id == bot.user.id:
        await ctx.send("No puedo aplicarme softban a mí mismo.")
        return
    if member_is_whitelisted(member, cfg):
        await ctx.send(f"{member.mention} está en la whitelist.")
        return

    try:
        await ctx.guild.ban(
            member,
            reason="Softban anti-raid",
            delete_message_seconds=7 * 24 * 60 * 60,
        )
        await ctx.guild.unban(member, reason="Softban anti-raid")
        cfg["bans_log"].append({"user": str(member.id), "time": now_ts(), "reason": "Softban"})
        save_db(db)
        await ctx.send(f"{member.mention} ha sido softbaneado.")
    except TypeError:
        await ctx.guild.ban(member, reason="Softban anti-raid")
        await ctx.guild.unban(member, reason="Softban anti-raid")
        cfg["bans_log"].append({"user": str(member.id), "time": now_ts(), "reason": "Softban"})
        save_db(db)
        await ctx.send(f"{member.mention} ha sido softbaneado.")
    except discord.DiscordException as exc:
        await ctx.send(f"No se pudo softbanear a {member.mention}: {exc}")


@bot.command(name="usertrack")
async def user_track(ctx: commands.Context, member: discord.Member = None):
    target = member or ctx.author
    cfg = get_guild_config(ctx.guild.id)
    stats = cfg.get("user_stats", {}).get(str(target.id), {"msgs": 0})

    embed = discord.Embed(
        title=f"Estadísticas de {target.display_name}",
        color=0x3498DB,
    )
    embed.add_field(name="Mensajes", value=str(stats.get("msgs", 0)), inline=True)
    embed.add_field(
        name="Uniones registradas",
        value=str(count_member_recent_joins(ctx.guild.id, target.id)),
        inline=True,
    )
    await ctx.send(embed=embed)


@bot.command(name="raidstats")
@commands.has_permissions(administrator=True)
async def raid_stats(ctx: commands.Context):
    await ctx.send(embed=build_stats_embed(ctx.guild.id))


@bot.command(name="top_spammers")
@commands.has_permissions(administrator=True)
async def top_spammers(ctx: commands.Context):
    cfg = get_guild_config(ctx.guild.id)
    guild_stats = cfg.get("user_stats", {})
    if not guild_stats:
        await ctx.send("No hay estadísticas todavía.")
        return

    sorted_stats = sorted(
        guild_stats.items(),
        key=lambda item: item[1].get("msgs", 0),
        reverse=True,
    )[:20]

    pages = []
    for page_start in range(0, len(sorted_stats), 5):
        lines = []
        slice_stats = sorted_stats[page_start : page_start + 5]
        for offset, (user_id, stats) in enumerate(slice_stats, start=page_start + 1):
            member = ctx.guild.get_member(int(user_id))
            name = member.display_name if member else f"Usuario {user_id}"
            lines.append(f"{offset}. **{name}** - {stats.get('msgs', 0)} mensajes")
        pages.append("\n".join(lines))

    view = Pagination(pages, "Top Spammers")
    view.ctx = ctx
    await ctx.send(embed=view.embed, view=view)


@bot.command(name="recent_joins")
@commands.has_permissions(administrator=True)
async def recent_joins_cmd(ctx: commands.Context):
    entries = list(recent_joins[str(ctx.guild.id)])
    if not entries:
        await ctx.send("No hay uniones recientes.")
        return

    pages = []
    for start in range(0, len(entries), 10):
        lines = []
        for entry in entries[start : start + 10]:
            member = ctx.guild.get_member(entry["user_id"])
            if member:
                lines.append(member.mention)
            else:
                lines.append(f"Usuario {entry['user_id']}")
        pages.append("\n".join(lines))

    view = Pagination(pages, "Miembros recientes")
    view.ctx = ctx
    await ctx.send(embed=view.embed, view=view)


@bot.command(name="lockchannel")
@commands.has_permissions(administrator=True)
async def lock_channel(ctx: commands.Context, channel: discord.TextChannel):
    cfg = get_guild_config(ctx.guild.id)
    cfg["channel_locks"][str(channel.id)] = True
    save_db(db)
    try:
        overwrite = channel.overwrites_for(ctx.guild.default_role)
        overwrite.send_messages = False
        await channel.set_permissions(ctx.guild.default_role, overwrite=overwrite)
        await ctx.send(f"{channel.mention} bloqueado.")
    except discord.DiscordException as exc:
        await ctx.send(f"No se pudo bloquear el canal: {exc}")


@bot.command(name="unlockchannel")
@commands.has_permissions(administrator=True)
async def unlock_channel(ctx: commands.Context, channel: discord.TextChannel):
    cfg = get_guild_config(ctx.guild.id)
    cfg["channel_locks"].pop(str(channel.id), None)
    save_db(db)
    try:
        overwrite = channel.overwrites_for(ctx.guild.default_role)
        overwrite.send_messages = None
        await channel.set_permissions(ctx.guild.default_role, overwrite=overwrite)
        await ctx.send(f"{channel.mention} desbloqueado.")
    except discord.DiscordException as exc:
        await ctx.send(f"No se pudo desbloquear el canal: {exc}")


@bot.command(name="rolelock")
@commands.has_permissions(administrator=True)
async def role_lock(ctx: commands.Context, role: discord.Role):
    cfg = get_guild_config(ctx.guild.id)
    cfg["role_locks"][str(role.id)] = True
    save_db(db)
    await ctx.send(f"Rol {role.mention} bloqueado para asignaciones futuras.")


@bot.command(name="unlockrole")
@commands.has_permissions(administrator=True)
async def role_unlock(ctx: commands.Context, role: discord.Role):
    cfg = get_guild_config(ctx.guild.id)
    cfg["role_locks"].pop(str(role.id), None)
    save_db(db)
    await ctx.send(f"Rol {role.mention} desbloqueado.")


@bot.command(name="captcha")
@commands.has_permissions(administrator=True)
async def captcha_toggle(ctx: commands.Context):
    cfg = get_guild_config(ctx.guild.id)
    cfg["captcha_enabled"] = not cfg.get("captcha_enabled", False)
    save_db(db)
    await ctx.send(f"Captcha: {'ACTIVADO' if cfg['captcha_enabled'] else 'DESACTIVADO'}")


@bot.command(name="vpncheck")
async def vpn_check(ctx: commands.Context, member: discord.Member):
    days_old = (discord.utils.utcnow() - member.created_at).days
    risk = "ALTO RIESGO" if days_old < 7 else "BAJO RIESGO"
    embed = discord.Embed(
        title=f"Verificación para {member.display_name}",
        description=f"Antigüedad: {days_old} días\nRiesgo estimado: {risk}",
        color=0x00BFFF,
    )
    await ctx.send(embed=embed)


@bot.command(name="masskick")
@commands.has_permissions(administrator=True)
async def mass_kick(ctx: commands.Context):
    async def callback(interaction: discord.Interaction, confirmed: bool):
        if not confirmed:
            await interaction.response.send_message("Acción cancelada.", ephemeral=True)
            return

        kicked_count = 0
        seven_days_ago = discord.utils.utcnow() - timedelta(days=7)
        for member in ctx.guild.members:
            if member.bot or member.id == bot.user.id:
                continue
            if member.created_at < seven_days_ago:
                continue
            try:
                await member.kick(reason="Cuenta nueva sospechosa (<7 días)")
                kicked_count += 1
            except discord.DiscordException as exc:
                logger.warning("Masskick falló con %s: %s", safe_member_name(member), exc)

        await interaction.response.send_message(f"{kicked_count} cuentas nuevas expulsadas.")

    embed = discord.Embed(
        title="Masskick de cuentas nuevas",
        description="¿Seguro que quieres expulsar cuentas creadas hace menos de 7 días?",
        color=0xFF0000,
    )
    await ctx.send(embed=embed, view=Confirm(callback))


@bot.tree.command(name="status", description="Verifica el estado del bot anti-raid.")
async def slash_status(interaction: discord.Interaction):
    if not interaction.guild:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    cfg = get_guild_config(interaction.guild.id)
    embed = discord.Embed(title="Estado del Bot Anti-Raid", color=0x00FF00)
    embed.add_field(name="Lockdown", value=str(cfg["lockdown"]), inline=True)
    embed.add_field(name="Captcha", value=str(cfg["captcha_enabled"]), inline=True)
    embed.add_field(name="Filtro enlaces", value=str(cfg["link_filter"]), inline=True)
    embed.add_field(name="Nitro protect", value=str(cfg["nitro_links"]), inline=True)
    embed.add_field(name="Lockdown mode", value=cfg["lockdown_mode"], inline=True)
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="lockdown", description="Activa o desactiva el lockdown del servidor.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_lockdown(interaction: discord.Interaction):
    if not interaction.guild:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    cfg = get_guild_config(interaction.guild.id)
    cfg["lockdown"] = not cfg["lockdown"]
    save_db(db)
    await interaction.response.send_message(
        f"Modo Lockdown: {'ACTIVADO' if cfg['lockdown'] else 'DESACTIVADO'}"
    )


@bot.tree.command(name="setlogchannel", description="Configura el canal de logs.")
@app_commands.describe(channel="Canal de logs")
@app_commands.checks.has_permissions(administrator=True)
async def slash_setlog(interaction: discord.Interaction, channel: discord.TextChannel):
    if not interaction.guild:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    cfg = get_guild_config(interaction.guild.id)
    cfg["log_channel"] = str(channel.id)
    save_db(db)
    await interaction.response.send_message(f"Canal de logs configurado: {channel.mention}")


@bot.tree.command(name="setalertchannel", description="Configura el canal de alertas.")
@app_commands.describe(channel="Canal de alertas")
@app_commands.checks.has_permissions(administrator=True)
async def slash_setalert(interaction: discord.Interaction, channel: discord.TextChannel):
    if not interaction.guild:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    cfg = get_guild_config(interaction.guild.id)
    cfg["alert_channel"] = str(channel.id)
    save_db(db)
    await interaction.response.send_message(f"Canal de alertas configurado: {channel.mention}")


@bot.tree.command(name="whitelist", description="Añade un miembro a la whitelist.")
@app_commands.describe(member="Miembro a añadir")
@app_commands.checks.has_permissions(administrator=True)
async def slash_whitelist(interaction: discord.Interaction, member: discord.Member):
    if not interaction.guild:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    cfg = get_guild_config(interaction.guild.id)
    if str(member.id) not in cfg["whitelist"]:
        cfg["whitelist"].append(str(member.id))
        save_db(db)
        await interaction.response.send_message(f"{member.mention} añadido a la whitelist.")
    else:
        await interaction.response.send_message(f"{member.mention} ya estaba en la whitelist.")


@bot.command(name="configdump")
@commands.has_permissions(administrator=True)
async def config_dump(ctx: commands.Context):
    cfg = get_guild_config(ctx.guild.id)
    embed = discord.Embed(title="Configuración del servidor", color=0xADD8E6)
    for key, value in cfg.items():
        rendered = str(value)
        if len(rendered) > 1000:
            rendered = rendered[:1000] + "..."
        embed.add_field(name=key, value=f"```{rendered}```", inline=False)
    await ctx.send(embed=embed)


@bot.command(name="config")
@commands.has_permissions(administrator=True)
async def config_edit(ctx: commands.Context, key: str, *, value: str):
    cfg = get_guild_config(ctx.guild.id)
    if key not in cfg:
        await ctx.send(f"La clave `{key}` no existe.")
        return

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        parsed = value

    cfg[key] = parsed
    save_db(db)
    await ctx.send(f"Configuración actualizada: `{key}` = `{parsed}`")


@bot.command(name="resetdb")
@commands.has_permissions(administrator=True)
async def reset_db(ctx: commands.Context):
    async def callback(interaction: discord.Interaction, confirmed: bool):
        if not confirmed:
            await interaction.response.send_message("Acción cancelada.", ephemeral=True)
            return

        db["guilds"][str(ctx.guild.id)] = copy.deepcopy(DEFAULT_GUILD_CONFIG)
        save_db(db)
        await interaction.response.send_message("Configuración del servidor restablecida.")

    embed = discord.Embed(
        title="Resetear base de datos",
        description="¿Seguro que quieres resetear toda la configuración del servidor?",
        color=0xFF0000,
    )
    await ctx.send(embed=embed, view=Confirm(callback))


@bot.command(name="backupdb")
@commands.has_permissions(administrator=True)
async def backup_db(ctx: commands.Context):
    config = get_guild_config(ctx.guild.id)
    payload = json.dumps(config, indent=2, ensure_ascii=False).encode("utf-8")
    file = discord.File(
        io.BytesIO(payload),
        filename=f"{ctx.guild.id}_backup_{int(now_ts())}.json",
    )
    await ctx.send("Backup generado:", file=file)


@bot.command(name="webhooklogs")
@commands.has_permissions(administrator=True)
async def webhook_logs_setup(ctx: commands.Context, url: str = None):
    cfg = get_guild_config(ctx.guild.id)
    if url:
        if "discord.com/api/webhooks/" not in url and "discordapp.com/api/webhooks/" not in url:
            await ctx.send("URL de webhook inválida.")
            return
        cfg["webhook_logs"] = url
        save_db(db)
        await ctx.send("Webhook de logs configurado.")
        return

    cfg["webhook_logs"] = None
    save_db(db)
    await ctx.send("Webhook de logs desactivado.")


@bot.command(name="alerttest")
@commands.has_permissions(administrator=True)
async def alert_test(ctx: commands.Context):
    await send_alert(ctx.guild.id, "Mensaje de prueba de alerta.")
    await ctx.send("Prueba de alerta enviada.")


@bot.command(name="lockdownmode")
@commands.has_permissions(administrator=True)
async def lockdown_mode(ctx: commands.Context, mode: str = "soft"):
    mode = mode.lower()
    if mode not in {"soft", "hard"}:
        await ctx.send("Modo inválido. Usa `soft` o `hard`.")
        return

    cfg = get_guild_config(ctx.guild.id)
    cfg["lockdown_mode"] = mode
    save_db(db)
    await ctx.send(f"Modo de lockdown: `{mode}`")


@bot.command(name="whitelistrole")
@commands.has_permissions(administrator=True)
async def whitelist_role(ctx: commands.Context, role: discord.Role):
    cfg = get_guild_config(ctx.guild.id)
    added = 0
    for member in role.members:
        if str(member.id) not in cfg["whitelist"]:
            cfg["whitelist"].append(str(member.id))
            added += 1
    save_db(db)
    await ctx.send(f"{added} miembros del rol {role.mention} añadidos a la whitelist.")


@bot.command(name="blacklistrole")
@commands.has_permissions(administrator=True)
async def blacklist_role(ctx: commands.Context, role: discord.Role):
    cfg = get_guild_config(ctx.guild.id)
    if str(role.id) not in cfg["blacklists"]:
        cfg["blacklists"].append(str(role.id))
        save_db(db)
    await ctx.send(f"Rol {role.mention} añadido a la blacklist.")


@bot.command(name="mutewave")
@commands.has_permissions(administrator=True)
async def mute_wave(ctx: commands.Context, duration: int):
    if not bot_has_perms(ctx.guild, ["moderate_members"]):
        await ctx.send("El bot no tiene permiso `moderate_members`.")
        return

    muted = 0
    entries = list(recent_joins[str(ctx.guild.id)])[-100:]
    for entry in entries:
        member = ctx.guild.get_member(entry["user_id"])
        if not member or member.bot or member.is_timed_out():
            continue
        try:
            await member.timeout(
                discord.utils.utcnow() + timedelta(minutes=duration),
                reason="Mute wave por uniones recientes",
            )
            muted += 1
        except discord.DiscordException as exc:
            logger.warning("No se pudo mutear a %s: %s", safe_member_name(member), exc)

    await ctx.send(f"{muted} miembros muteados por {duration} minutos.")


@bot.command(name="unmuteall")
@commands.has_permissions(administrator=True)
async def unmute_all(ctx: commands.Context):
    if not bot_has_perms(ctx.guild, ["moderate_members"]):
        await ctx.send("El bot no tiene permiso `moderate_members`.")
        return

    unmuted = 0
    for member in ctx.guild.members:
        if not member.is_timed_out():
            continue
        try:
            await member.timeout(None, reason="Desmuteo general")
            unmuted += 1
        except discord.DiscordException as exc:
            logger.warning("No se pudo desmutear a %s: %s", safe_member_name(member), exc)

    await ctx.send(f"{unmuted} miembros desmuteados.")


@bot.command(name="kickrecent")
@commands.has_permissions(administrator=True)
async def kick_recent(ctx: commands.Context, n: int = 10):
    if not bot_has_perms(ctx.guild, ["kick_members"]):
        await ctx.send("El bot no tiene permiso `kick_members`.")
        return

    kicked = 0
    entries = list(recent_joins[str(ctx.guild.id)])[-max(1, n) :]
    cfg = get_guild_config(ctx.guild.id)
    for entry in entries:
        member = ctx.guild.get_member(entry["user_id"])
        if not member or member.bot or member_is_whitelisted(member, cfg):
            continue
        try:
            await member.kick(reason="Kick por unirse recientemente")
            kicked += 1
        except discord.DiscordException as exc:
            logger.warning("No se pudo expulsar a %s: %s", safe_member_name(member), exc)

    await ctx.send(f"{kicked} de los últimos {n} miembros fueron expulsados.")


@bot.command(name="banspammer")
@commands.has_permissions(administrator=True)
async def ban_spammer(ctx: commands.Context, member: discord.Member):
    cfg = get_guild_config(ctx.guild.id)
    stats = cfg.get("user_stats", {}).get(str(member.id), {"msgs": 0})
    spam_threshold = cfg.get("threshold_msgs", 8) * 2
    days_old = (discord.utils.utcnow() - member.created_at).days
    age_factor = 0.5 if days_old < 7 else 1.0

    if stats["msgs"] * age_factor <= spam_threshold:
        await ctx.send(
            f"{member.mention} no cumple criterios de ban. Mensajes: {stats['msgs']}, edad: {days_old} días."
        )
        return

    if not bot_has_perms(ctx.guild, ["ban_members"]):
        await ctx.send("El bot no tiene permiso `ban_members`.")
        return

    try:
        await ctx.guild.ban(member, reason="Spammer activo")
        cfg["bans_log"].append({"user": str(member.id), "time": now_ts(), "reason": "Spammer activo"})
        save_db(db)
        await ctx.send(f"{member.mention} baneado por spam activo.")
    except discord.DiscordException as exc:
        await ctx.send(f"No se pudo banear a {member.mention}: {exc}")


@bot.command(name="warns")
async def warns_view(ctx: commands.Context, member: discord.Member = None):
    target = member or ctx.author
    cfg = get_guild_config(ctx.guild.id)
    warns = cfg.get("warns", {}).get(str(target.id), [])
    if not warns:
        await ctx.send(f"{target.mention} no tiene advertencias.")
        return

    embed = discord.Embed(title=f"Advertencias de {target.display_name}", color=0xFFA500)
    for warn in warns[-5:]:
        embed.add_field(
            name=f"Advertencia ({warn.get('timestamp', 'sin fecha')})",
            value=warn.get("reason", "Sin motivo"),
            inline=False,
        )
    await ctx.send(embed=embed)


@bot.command(name="strikes")
async def strikes_view(ctx: commands.Context, member: discord.Member = None):
    target = member or ctx.author
    cfg = get_guild_config(ctx.guild.id)
    total = len(cfg.get("strikes", {}).get(str(target.id), []))
    embed = discord.Embed(
        title=f"Strikes de {target.display_name}",
        description=f"{total} strikes acumulados.",
        color=0xFF4500,
    )
    await ctx.send(embed=embed)


@bot.command(name="forgive")
@commands.has_permissions(administrator=True)
async def forgive(ctx: commands.Context, member: discord.Member):
    cfg = get_guild_config(ctx.guild.id)
    cfg.get("warns", {}).pop(str(member.id), None)
    cfg.get("strikes", {}).pop(str(member.id), None)
    save_db(db)
    await ctx.send(f"{member.mention} ha sido perdonado.")


@bot.command(name="auditlog")
async def audit_log(ctx: commands.Context):
    cfg = get_guild_config(ctx.guild.id)
    bans_count = len(cfg.get("bans_log", []))
    kicks_count = 0

    if bot_has_perms(ctx.guild, ["view_audit_log"]):
        try:
            async for _entry in ctx.guild.audit_logs(action=discord.AuditLogAction.kick, limit=100):
                kicks_count += 1
        except discord.DiscordException as exc:
            logger.warning("No se pudo leer audit log: %s", exc)

    embed = discord.Embed(title="Resumen de auditoría", color=0x8A2BE2)
    embed.add_field(name="Baneos registrados", value=str(bans_count), inline=True)
    embed.add_field(name="Kicks recientes", value=str(kicks_count), inline=True)
    embed.add_field(name="Incidentes de spam", value=str(cfg.get("spam_incidents", 0)), inline=True)
    await ctx.send(embed=embed)


@bot.command(name="membercount")
async def member_count(ctx: commands.Context):
    embed = discord.Embed(title="Conteo de miembros", color=0x9370DB)
    embed.add_field(name="Total", value=str(ctx.guild.member_count), inline=True)
    embed.add_field(name="Nuevos en 24h", value=str(count_recent_joins(ctx.guild.id, 86400)), inline=True)
    await ctx.send(embed=embed)


@bot.command(name="botperms")
async def bot_perms(ctx: commands.Context):
    bot_member = get_bot_member(ctx.guild)
    if not bot_member:
        await ctx.send("No pude localizar al bot en este servidor.")
        return

    enabled = [name for name, value in bot_member.guild_permissions if value]
    rendered = ", ".join(enabled) if enabled else "Sin permisos"
    embed = discord.Embed(title="Permisos del bot", color=0x6A5ACD)
    embed.add_field(name="Permisos habilitados", value=f"```{rendered[:3900]}```", inline=False)
    await ctx.send(embed=embed)


@bot.command(name="sync")
@commands.has_permissions(administrator=True)
async def sync_slash(ctx: commands.Context):
    try:
        synced = await bot.tree.sync()
        await ctx.send(f"Se sincronizaron {len(synced)} comandos slash.")
    except discord.HTTPException as exc:
        await ctx.send(f"No se pudieron sincronizar los comandos slash: {exc}")


@blacklist_add.error
async def blacklist_add_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.BadArgument):
        await ctx.send("Debes mencionar un miembro o un rol válido.")


if __name__ == "__main__":
    bot.run(TOKEN)
