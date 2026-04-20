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
from typing import Callable, Optional

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
HELP_PREFIX = "!ghelp"

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

CONFIG_EDITABLE_KEYS = {
    "threshold_joins": int,
    "threshold_msgs": int,
    "mention_limit": int,
    "emoji_limit": int,
    "invite_spam_limit": int,
    "slowmode_duration": int,
    "antispam_level": int,
}

INVITE_REGEX = re.compile(
    r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord(?:app)?\.com/invite)/[A-Za-z0-9-]+",
    re.IGNORECASE,
)
CUSTOM_EMOJI_REGEX = re.compile(r"<a?:\w+:\d+>")

TOGGLE_CHOICES = [
    app_commands.Choice(name="Activar", value="enable"),
    app_commands.Choice(name="Desactivar", value="disable"),
    app_commands.Choice(name="Invertir", value="toggle"),
]

LOCKDOWN_MODE_CHOICES = [
    app_commands.Choice(name="Soft", value="soft"),
    app_commands.Choice(name="Hard", value="hard"),
]

WEBHOOK_ACTION_CHOICES = [
    app_commands.Choice(name="Configurar", value="set"),
    app_commands.Choice(name="Eliminar", value="clear"),
]

CONFIG_KEY_CHOICES = [
    app_commands.Choice(name="threshold_joins", value="threshold_joins"),
    app_commands.Choice(name="threshold_msgs", value="threshold_msgs"),
    app_commands.Choice(name="mention_limit", value="mention_limit"),
    app_commands.Choice(name="emoji_limit", value="emoji_limit"),
    app_commands.Choice(name="invite_spam_limit", value="invite_spam_limit"),
    app_commands.Choice(name="slowmode_duration", value="slowmode_duration"),
    app_commands.Choice(name="antispam_level", value="antispam_level"),
]

HELP_SECTIONS = {
    "general": {
        "title": "Ayuda General",
        "description": "Comandos informativos y de ayuda.",
        "entries": [
            ("!ghelp", "Abre esta ayuda interactiva por prefijo.", "!ghelp"),
            ("/ghelp", "Abre la ayuda interactiva en slash.", "/ghelp"),
            ("/status", "Muestra el estado actual del bot.", "/status"),
            ("/dashboard", "Resumen rapido de protecciones y metricas.", "/dashboard"),
            ("/riskscore", "Calcula el riesgo actual del servidor.", "/riskscore"),
            ("/raidstats", "Muestra estadisticas anti-raid.", "/raidstats"),
            ("/membercount", "Muestra total y altas recientes.", "/membercount"),
            ("/usertrack", "Consulta mensajes y actividad de un miembro.", "/usertrack member:@usuario"),
            ("/top_spammers", "Lista a los usuarios con mas mensajes.", "/top_spammers"),
            ("/recent_joins", "Lista las uniones recientes.", "/recent_joins"),
            ("/warns", "Muestra advertencias registradas.", "/warns member:@usuario"),
            ("/strikes", "Muestra strikes registrados.", "/strikes member:@usuario"),
            ("/auditlog", "Resumen del registro de auditoria.", "/auditlog"),
            ("/botperms", "Muestra permisos actuales del bot.", "/botperms"),
        ],
    },
    "security": {
        "title": "Proteccion",
        "description": "Comandos de anti-raid, filtros y endurecimiento.",
        "entries": [
            ("/lockdown", "Activa, desactiva o invierte el lockdown.", "/lockdown mode:Activar"),
            ("/panicmode", "Activa el modo de panico del servidor.", "/panicmode"),
            ("/lockdownmode", "Elige el modo soft o hard.", "/lockdownmode mode:Hard"),
            ("/captcha", "Activa o desactiva captcha para nuevos usuarios.", "/captcha mode:Activar"),
            ("/linkfilter", "Activa o desactiva el filtro de enlaces.", "/linkfilter mode:Activar"),
            ("/nitroprotect", "Activa o desactiva la proteccion Nitro scam.", "/nitroprotect mode:Activar"),
            ("/mentionspam", "Ajusta el limite de menciones por mensaje.", "/mentionspam limit:5"),
            ("/emojispam", "Ajusta el limite de emojis personalizados.", "/emojispam limit:5"),
            ("/invitespam", "Ajusta el limite de invitaciones por mensaje.", "/invitespam limit:3"),
            ("/patternban", "Agrega una regex de baneo por contenido.", "/patternban pattern:(spam|raid)"),
            ("/setverifyrole", "Configura el rol de verificacion.", "/setverifyrole role:@verificado"),
            ("/saferole", "Asigna el rol de verificacion a quien le falte.", "/saferole"),
            ("/setlogchannel", "Configura el canal de logs.", "/setlogchannel channel:#logs"),
            ("/setalertchannel", "Configura el canal de alertas.", "/setalertchannel channel:#alertas"),
            ("/webhooklogs", "Configura o elimina el webhook de logs.", "/webhooklogs action:Configurar url:https://..."),
            ("/alerttest", "Envia una alerta de prueba.", "/alerttest"),
            ("/controlpanel", "Abre un panel con botones de control rapido.", "/controlpanel"),
        ],
    },
    "moderation": {
        "title": "Moderacion",
        "description": "Comandos para listas, locks y acciones masivas.",
        "entries": [
            ("/whitelist", "Agrega un miembro a la whitelist.", "/whitelist member:@usuario"),
            ("/whitelistrole", "Agrega a la whitelist a todos los miembros de un rol.", "/whitelistrole role:@staff"),
            ("/blacklist", "Agrega un miembro a la blacklist.", "/blacklist member:@usuario"),
            ("/blacklistrole", "Agrega un rol a la blacklist.", "/blacklistrole role:@raiders"),
            ("/lockchannel", "Bloquea un canal de texto.", "/lockchannel channel:#general"),
            ("/unlockchannel", "Desbloquea un canal de texto.", "/unlockchannel channel:#general"),
            ("/rolelock", "Bloquea la asignacion de un rol.", "/rolelock role:@admin"),
            ("/unlockrole", "Quita el bloqueo de un rol.", "/unlockrole role:@admin"),
            ("/softban", "Ban + unban para limpiar mensajes.", "/softban member:@usuario"),
            ("/banspammer", "Banea a un spammer activo si supera el umbral.", "/banspammer member:@usuario"),
            ("/banwave", "Banea a todos los miembros de un rol.", "/banwave role:@raiders"),
            ("/masskick", "Expulsa cuentas nuevas sospechosas.", "/masskick"),
            ("/mutewave", "Timeout a las cuentas recien unidas.", "/mutewave duration:15"),
            ("/unmuteall", "Quita todos los timeouts activos.", "/unmuteall"),
            ("/kickrecent", "Expulsa a los ultimos N miembros que entraron.", "/kickrecent amount:10"),
            ("/forgive", "Borra warns y strikes de un miembro.", "/forgive member:@usuario"),
        ],
    },
    "system": {
        "title": "Sistema",
        "description": "Comandos de configuracion, exportacion y sincronizacion.",
        "entries": [
            ("/configdump", "Muestra la configuracion del servidor.", "/configdump"),
            ("/config", "Edita una clave segura mediante opciones.", "/config key:threshold_msgs value:12"),
            ("/backupdb", "Exporta la configuracion a JSON.", "/backupdb"),
            ("/resetdb", "Restaura la configuracion por defecto.", "/resetdb"),
            ("/sync", "Sincroniza comandos slash.", "/sync"),
            ("/vpncheck", "Evalua el riesgo de una cuenta por antiguedad.", "/vpncheck member:@usuario"),
        ],
    },
}


intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.guilds = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)


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


def now_ts() -> float:
    return time.time()


def truncate(text: str, limit: int = 1000) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def load_jsonish(value: str):
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


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


def count_recent_joins(guild_id: int, seconds: int = 86400) -> int:
    current = now_ts()
    return sum(
        1
        for entry in recent_joins[str(guild_id)]
        if current - entry["joined_at"] < seconds
    )


def count_member_recent_joins(guild_id: int, user_id: int) -> int:
    return sum(
        1
        for entry in recent_joins[str(guild_id)]
        if entry["user_id"] == user_id
    )


def get_bot_member(guild: discord.Guild):
    if bot.user is None:
        return None
    return guild.me or guild.get_member(bot.user.id)


def bot_has_perms(guild: discord.Guild, needed: list[str]) -> bool:
    bot_member = get_bot_member(guild)
    if not bot_member:
        return False
    permissions = bot_member.guild_permissions
    return all(getattr(permissions, name, False) for name in needed)


def apply_toggle_mode(current: bool, mode: str) -> bool:
    if mode == "enable":
        return True
    if mode == "disable":
        return False
    return not current


def build_stats_embed(guild_id: int) -> discord.Embed:
    cfg = get_guild_config(guild_id)
    embed = discord.Embed(title="Anti-Raid Stats", color=0xFF9900)
    embed.add_field(name="Lockdown", value=str(cfg["lockdown"]), inline=True)
    embed.add_field(name="Whitelist", value=str(len(cfg["whitelist"])), inline=True)
    embed.add_field(name="Spam incidents", value=str(cfg["spam_incidents"]), inline=True)

    graph_fill = "#" * min(20, cfg["spam_incidents"] // 2)
    graph_empty = "-" * (20 - len(graph_fill))
    embed.add_field(name="Spam graph", value=f"[{graph_fill}{graph_empty}]", inline=False)
    return embed


def build_status_embed(guild: discord.Guild) -> discord.Embed:
    cfg = get_guild_config(guild.id)
    embed = discord.Embed(
        title=f"Estado de {guild.name}",
        description="Resumen principal del sistema Guardian.",
        color=0x2ECC71,
    )
    embed.add_field(name="Lockdown", value="ON" if cfg["lockdown"] else "OFF", inline=True)
    embed.add_field(name="Captcha", value="ON" if cfg["captcha_enabled"] else "OFF", inline=True)
    embed.add_field(name="Link filter", value="ON" if cfg["link_filter"] else "OFF", inline=True)
    embed.add_field(name="Nitro protect", value="ON" if cfg["nitro_links"] else "OFF", inline=True)
    embed.add_field(name="Lockdown mode", value=cfg["lockdown_mode"], inline=True)
    embed.add_field(name="Spam incidents", value=str(cfg["spam_incidents"]), inline=True)
    return embed


def build_dashboard_embed(guild: discord.Guild) -> discord.Embed:
    cfg = get_guild_config(guild.id)
    embed = discord.Embed(
        title="Guardian Dashboard",
        description="Vista rapida de protecciones, actividad y ajustes.",
        color=0x00BFFF,
    )
    embed.add_field(name="Lockdown", value="ON" if cfg["lockdown"] else "OFF", inline=True)
    embed.add_field(name="Captcha", value="ON" if cfg["captcha_enabled"] else "OFF", inline=True)
    embed.add_field(name="Links", value="ON" if cfg["link_filter"] else "OFF", inline=True)
    embed.add_field(name="Nitro", value="ON" if cfg["nitro_links"] else "OFF", inline=True)
    embed.add_field(name="Mention limit", value=str(cfg["mention_limit"]), inline=True)
    embed.add_field(name="Emoji limit", value=str(cfg["emoji_limit"]), inline=True)
    embed.add_field(name="Invite limit", value=str(cfg["invite_spam_limit"]), inline=True)
    embed.add_field(name="Threshold joins", value=str(cfg["threshold_joins"]), inline=True)
    embed.add_field(name="Threshold msgs", value=str(cfg["threshold_msgs"]), inline=True)
    embed.add_field(name="Recent joins 24h", value=str(count_recent_joins(guild.id)), inline=True)
    embed.add_field(name="Ban patterns", value=str(len(cfg["ban_patterns"])), inline=True)
    embed.add_field(name="Role locks", value=str(len(cfg["role_locks"])), inline=True)
    return embed


def build_control_panel_embed(guild: discord.Guild) -> discord.Embed:
    cfg = get_guild_config(guild.id)
    embed = discord.Embed(
        title="Panel de Control Guardian",
        description="Botones para cambios rapidos de seguridad.",
        color=0x5865F2,
    )
    embed.add_field(name="Lockdown", value="ON" if cfg["lockdown"] else "OFF", inline=True)
    embed.add_field(name="Captcha", value="ON" if cfg["captcha_enabled"] else "OFF", inline=True)
    embed.add_field(name="Link filter", value="ON" if cfg["link_filter"] else "OFF", inline=True)
    embed.add_field(name="Nitro protect", value="ON" if cfg["nitro_links"] else "OFF", inline=True)
    embed.add_field(name="Modo", value=cfg["lockdown_mode"], inline=True)
    embed.add_field(name="Spam incidents", value=str(cfg["spam_incidents"]), inline=True)
    embed.set_footer(text="Panel privado del administrador.")
    return embed


def build_help_embed(section_key: str) -> discord.Embed:
    section = HELP_SECTIONS[section_key]
    embed = discord.Embed(
        title=section["title"],
        description=section["description"],
        color=0x5865F2,
    )
    lines = []
    for name, desc, example in section["entries"]:
        lines.append(f"`{name}`\n{desc}\nEjemplo: `{example}`")
    embed.description = section["description"] + "\n\n" + "\n\n".join(lines)
    embed.set_footer(text="Usa los botones para cambiar de categoria.")
    return embed


def build_member_stats_embed(guild: discord.Guild, member: discord.Member) -> discord.Embed:
    cfg = get_guild_config(guild.id)
    stats = cfg.get("user_stats", {}).get(str(member.id), {"msgs": 0})
    embed = discord.Embed(
        title=f"Actividad de {member.display_name}",
        color=0x3498DB,
    )
    embed.add_field(name="Mensajes", value=str(stats.get("msgs", 0)), inline=True)
    embed.add_field(
        name="Uniones registradas",
        value=str(count_member_recent_joins(guild.id, member.id)),
        inline=True,
    )
    embed.add_field(name="Cuenta creada", value=discord.utils.format_dt(member.created_at, "R"), inline=True)
    return embed


def build_membercount_embed(guild: discord.Guild) -> discord.Embed:
    embed = discord.Embed(title="Conteo de miembros", color=0x9370DB)
    embed.add_field(name="Total", value=str(guild.member_count), inline=True)
    embed.add_field(name="Nuevos en 24h", value=str(count_recent_joins(guild.id)), inline=True)
    return embed


def build_bot_permissions_embed(guild: discord.Guild) -> discord.Embed:
    bot_member = get_bot_member(guild)
    embed = discord.Embed(title="Permisos del bot", color=0x6A5ACD)
    if not bot_member:
        embed.description = "No pude localizar al bot en este servidor."
        return embed

    enabled = [name for name, value in bot_member.guild_permissions if value]
    embed.add_field(
        name="Permisos habilitados",
        value=f"```{truncate(', '.join(enabled) or 'Sin permisos', 3900)}```",
        inline=False,
    )
    return embed


def build_warns_embed(member: discord.Member, warns: list[dict]) -> discord.Embed:
    embed = discord.Embed(title=f"Advertencias de {member.display_name}", color=0xFFA500)
    if not warns:
        embed.description = "No hay advertencias registradas."
        return embed
    for warn in warns[-5:]:
        embed.add_field(
            name=f"Warn ({warn.get('timestamp', 'sin fecha')})",
            value=warn.get("reason", "Sin motivo"),
            inline=False,
        )
    return embed


def build_strikes_embed(member: discord.Member, strikes: list[dict]) -> discord.Embed:
    embed = discord.Embed(title=f"Strikes de {member.display_name}", color=0xFF4500)
    embed.description = f"{len(strikes)} strikes acumulados."
    return embed


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
            await channel.send(f"[ALERTA] {message}")
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


async def set_lockdown_state(guild: discord.Guild, enabled: bool, reason: str):
    cfg = get_guild_config(guild.id)
    cfg["lockdown"] = enabled
    if enabled:
        cfg["raid_history"].append(
            {
                "timestamp": now_ts(),
                "reason": reason,
                "mode": cfg.get("lockdown_mode", "soft"),
            }
        )
        await send_alert(guild.id, f"Lockdown activado: {reason}")
        await send_log(guild.id, f"Lockdown activado: {reason}")
    else:
        await send_alert(guild.id, "Lockdown desactivado manualmente.")
        await send_log(guild.id, "Lockdown desactivado manualmente.")
    save_db(db)


async def trigger_lockdown(guild: discord.Guild):
    cfg = get_guild_config(guild.id)
    if cfg["lockdown"]:
        return

    await set_lockdown_state(guild, True, "Raid detectado por uniones masivas")
    await send_webhook(guild.id, "PANIC LOCKDOWN")

    if cfg.get("lockdown_mode", "soft") != "hard":
        await send_log(guild.id, "PANIC MODE (SOFT) activado.")
        return

    if not bot_has_perms(guild, ["kick_members"]):
        await send_alert(guild.id, "No tengo permisos para expulsar miembros en lockdown hard.")
        return

    kicked = 0
    for member in guild.members:
        if member.bot or member_is_whitelisted(member, cfg):
            continue
        try:
            await member.kick(reason="PANIC Anti-Raid")
            kicked += 1
        except discord.DiscordException as exc:
            logger.warning("No se pudo expulsar a %s (%s): %s", member, member.id, exc)

    await send_log(guild.id, f"{kicked} miembros expulsados durante PANIC MODE (HARD)")


class Pagination(View):
    def __init__(self, title: str, pages: list[str], owner_id: Optional[int] = None):
        super().__init__(timeout=300)
        self.title = title
        self.pages = pages or ["No hay contenido para mostrar."]
        self.owner_id = owner_id
        self.page = 0
        self._refresh_buttons()

    def build_embed(self) -> discord.Embed:
        embed = discord.Embed(title=self.title, description=self.pages[self.page], color=0x2F3136)
        embed.set_footer(text=f"Pagina {self.page + 1}/{len(self.pages)}")
        return embed

    def _refresh_buttons(self):
        self.prev_button.disabled = self.page == 0
        self.next_button.disabled = self.page >= len(self.pages) - 1

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if self.owner_id is None:
            return True
        if interaction.user.id == self.owner_id:
            return True
        await interaction.response.send_message("Solo quien abrio esta vista puede usar estos botones.", ephemeral=True)
        return False

    @discord.ui.button(label="Anterior", style=discord.ButtonStyle.secondary)
    async def prev_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        if self.page > 0:
            self.page -= 1
        self._refresh_buttons()
        await interaction.response.edit_message(embed=self.build_embed(), view=self)

    @discord.ui.button(label="Siguiente", style=discord.ButtonStyle.secondary)
    async def next_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        if self.page < len(self.pages) - 1:
            self.page += 1
        self._refresh_buttons()
        await interaction.response.edit_message(embed=self.build_embed(), view=self)

    @discord.ui.button(label="Cerrar", style=discord.ButtonStyle.danger)
    async def stop_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(embed=self.build_embed(), view=self)
        self.stop()


class Confirm(View):
    def __init__(self, owner_id: int, callback: Callable[[discord.Interaction, bool], asyncio.Future]):
        super().__init__(timeout=60)
        self.owner_id = owner_id
        self.callback = callback

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.owner_id:
            return True
        await interaction.response.send_message("Solo quien inicio esta accion puede confirmarla.", ephemeral=True)
        return False

    @discord.ui.button(label="Confirmar", style=discord.ButtonStyle.green)
    async def confirm_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        self.stop()
        await self.callback(interaction, True)

    @discord.ui.button(label="Cancelar", style=discord.ButtonStyle.red)
    async def cancel_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        self.stop()
        await self.callback(interaction, False)


class HelpCenterView(View):
    def __init__(self, guild: Optional[discord.Guild]):
        super().__init__(timeout=600)
        self.guild = guild
        self.current_section = "general"

    @discord.ui.button(label="General", style=discord.ButtonStyle.primary)
    async def general_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        self.current_section = "general"
        await interaction.response.edit_message(embed=build_help_embed("general"), view=self)

    @discord.ui.button(label="Proteccion", style=discord.ButtonStyle.primary)
    async def security_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        self.current_section = "security"
        await interaction.response.edit_message(embed=build_help_embed("security"), view=self)

    @discord.ui.button(label="Moderacion", style=discord.ButtonStyle.primary)
    async def moderation_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        self.current_section = "moderation"
        await interaction.response.edit_message(embed=build_help_embed("moderation"), view=self)

    @discord.ui.button(label="Sistema", style=discord.ButtonStyle.primary)
    async def system_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        self.current_section = "system"
        await interaction.response.edit_message(embed=build_help_embed("system"), view=self)

    @discord.ui.button(label="Panel Admin", style=discord.ButtonStyle.success)
    async def admin_panel_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        if interaction.guild is None:
            await interaction.response.send_message("Este boton solo funciona dentro de un servidor.", ephemeral=True)
            return
        if not interaction.user.guild_permissions.administrator:
            await interaction.response.send_message("Necesitas permisos de administrador.", ephemeral=True)
            return
        panel_view = AdminControlView(interaction.guild, interaction.user.id)
        await interaction.response.send_message(
            embed=build_control_panel_embed(interaction.guild),
            view=panel_view,
            ephemeral=True,
        )


class AdminControlView(View):
    def __init__(self, guild: discord.Guild, owner_id: int):
        super().__init__(timeout=600)
        self.guild_id = guild.id
        self.owner_id = owner_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.guild is None or interaction.guild.id != self.guild_id:
            await interaction.response.send_message("Este panel ya no pertenece a este servidor.", ephemeral=True)
            return False
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message("Este panel es privado.", ephemeral=True)
            return False
        if not interaction.user.guild_permissions.administrator:
            await interaction.response.send_message("Necesitas permisos de administrador.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Lockdown", style=discord.ButtonStyle.danger)
    async def lockdown_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        cfg = get_guild_config(interaction.guild.id)
        await set_lockdown_state(interaction.guild, not cfg["lockdown"], f"Panel rapido por {interaction.user}")
        await interaction.response.edit_message(embed=build_control_panel_embed(interaction.guild), view=self)

    @discord.ui.button(label="Captcha", style=discord.ButtonStyle.secondary)
    async def captcha_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        cfg = get_guild_config(interaction.guild.id)
        cfg["captcha_enabled"] = not cfg["captcha_enabled"]
        save_db(db)
        await interaction.response.edit_message(embed=build_control_panel_embed(interaction.guild), view=self)

    @discord.ui.button(label="Links", style=discord.ButtonStyle.secondary)
    async def link_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        cfg = get_guild_config(interaction.guild.id)
        cfg["link_filter"] = not cfg["link_filter"]
        save_db(db)
        await interaction.response.edit_message(embed=build_control_panel_embed(interaction.guild), view=self)

    @discord.ui.button(label="Nitro", style=discord.ButtonStyle.secondary)
    async def nitro_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        cfg = get_guild_config(interaction.guild.id)
        cfg["nitro_links"] = not cfg["nitro_links"]
        save_db(db)
        await interaction.response.edit_message(embed=build_control_panel_embed(interaction.guild), view=self)

    @discord.ui.button(label="Panic", style=discord.ButtonStyle.danger, row=1)
    async def panic_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        await trigger_lockdown(interaction.guild)
        await interaction.response.edit_message(embed=build_control_panel_embed(interaction.guild), view=self)

    @discord.ui.button(label="Refrescar", style=discord.ButtonStyle.success, row=1)
    async def refresh_button(self, interaction: discord.Interaction, _button: discord.ui.Button):
        await interaction.response.edit_message(embed=build_control_panel_embed(interaction.guild), view=self)


@bot.event
async def on_ready():
    logger.info("Guardian online como %s", bot.user)
    try:
        synced = await bot.tree.sync()
        logger.info("Slash commands sincronizados: %s", len(synced))
    except discord.HTTPException as exc:
        logger.error("No se pudieron sincronizar slash commands: %s", exc)

    await bot.change_presence(activity=discord.Game(name="Guardian Mode"), status=discord.Status.online)


@bot.event
async def on_member_join(member: discord.Member):
    guild_id = member.guild.id
    cfg = get_guild_config(guild_id)

    recent_joins[str(guild_id)].append({"user_id": member.id, "joined_at": now_ts()})
    join_tracker[guild_id].append(now_ts())

    if member_is_blacklisted(member, cfg):
        await send_log(guild_id, f"Usuario en blacklist detectado: {member.mention}. Expulsando.")
        try:
            await member.kick(reason="Usuario o rol en blacklist")
        except discord.DiscordException as exc:
            await send_alert(guild_id, f"No pude expulsar a {member.mention}: {exc}")
        return

    if member_is_whitelisted(member, cfg):
        await send_log(guild_id, f"Usuario en whitelist unido: {member.mention}")
        return

    if cfg.get("verify_role"):
        role = member.guild.get_role(int(cfg["verify_role"]))
        if role:
            try:
                await member.add_roles(role, reason="Auto verify role")
            except discord.DiscordException as exc:
                logger.warning("No se pudo asignar verify role a %s (%s): %s", member, member.id, exc)

    await send_log(guild_id, f"Join: {member.mention} ({member.id})")

    if cfg.get("captcha_enabled", False):
        try:
            a, b = random.randint(1, 10), random.randint(1, 10)
            await member.send(f"Bienvenido. Responde esta suma para verificarte: {a} + {b} = ?")

            def check(message: discord.Message):
                return (
                    message.author.id == member.id
                    and isinstance(message.channel, discord.DMChannel)
                    and message.content.isdigit()
                )

            reply = await bot.wait_for("message", check=check, timeout=300)
            if int(reply.content) != a + b:
                try:
                    await member.send("Respuesta incorrecta. Seras expulsado.")
                except discord.DiscordException:
                    pass
                await member.kick(reason="Captcha incorrecto")
                await send_log(guild_id, f"Captcha fallido: {member.mention}")
                return

            try:
                await member.send("Verificacion completada.")
            except discord.DiscordException:
                pass
            await send_log(guild_id, f"Captcha superado: {member.mention}")
        except asyncio.TimeoutError:
            try:
                await member.send("Tiempo agotado. Seras expulsado.")
            except discord.DiscordException:
                pass
            try:
                await member.kick(reason="Captcha timeout")
            except discord.DiscordException:
                pass
            await send_log(guild_id, f"Captcha timeout: {member.mention}")
            return
        except discord.Forbidden:
            await send_log(guild_id, f"No pude abrir DM con {member.mention} para captcha.")
        except discord.DiscordException as exc:
            logger.warning("Error en captcha para %s (%s): %s", member, member.id, exc)

    if is_raid_join(guild_id):
        await trigger_lockdown(member.guild)


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    guild = message.guild
    guild_id = guild.id
    cfg = get_guild_config(guild_id)
    content_lower = message.content.lower()
    is_prefix_help = content_lower.startswith(HELP_PREFIX)

    if not isinstance(message.author, discord.Member):
        if is_prefix_help:
            await bot.process_commands(message)
        return

    member = message.author
    record_user_message(guild_id, member.id)
    msg_tracker[guild_id][member.id].append(now_ts())

    if member_is_blacklisted(member, cfg):
        try:
            await message.delete()
            await send_log(guild_id, f"Mensaje borrado de usuario/rol en blacklist: {member.mention}")
        except discord.DiscordException:
            pass
        return

    deleted = False

    async def delete_and_report(log_text: str, alert_text: str):
        nonlocal deleted
        if deleted or is_prefix_help:
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
        if cfg.get("link_filter") and ("http://" in content_lower or "https://" in content_lower):
            await delete_and_report(
                f"Enlace eliminado de {member.mention} ({member.id})",
                f"Enlace eliminado de {member.mention}",
            )

        if len(message.mentions) > cfg.get("mention_limit", 5):
            await delete_and_report(
                f"Mention spam de {member.mention} ({member.id})",
                f"Mention spam de {member.mention}",
            )

        if len(CUSTOM_EMOJI_REGEX.findall(message.content)) > cfg.get("emoji_limit", 5):
            await delete_and_report(
                f"Emoji spam de {member.mention} ({member.id})",
                f"Emoji spam de {member.mention}",
            )

        if cfg.get("nitro_links") and "discord.gift/" in content_lower:
            await delete_and_report(
                f"Nitro scam detectado en mensaje de {member.mention}",
                f"Nitro scam detectado en mensaje de {member.mention}",
            )

        invite_count = len(INVITE_REGEX.findall(message.content))
        if invite_count >= cfg.get("invite_spam_limit", 3):
            await delete_and_report(
                f"Invite spam de {member.mention} ({invite_count} invitaciones)",
                f"Invite spam de {member.mention}",
            )

        for pattern in cfg.get("ban_patterns", []):
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                logger.warning("Regex invalida '%s': %s", pattern, exc)
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
                        await send_log(guild_id, f"Pattern ban a {member.mention} por `{pattern}`")
                        await send_alert(guild_id, f"Pattern ban a {member.mention}")
                    except discord.DiscordException as exc:
                        await send_alert(guild_id, f"No se pudo banear a {member.mention}: {exc}")
                break

        if is_spam(guild_id, member.id) and bot_has_perms(guild, ["moderate_members"]):
            try:
                await member.timeout(
                    discord.utils.utcnow() + timedelta(minutes=10),
                    reason="Spam detectado",
                )
                cfg["spam_incidents"] += 1
                await send_log(guild_id, f"Timeout a {member.mention} por spam")
                await send_alert(guild_id, f"Timeout a {member.mention} por spam")
            except discord.DiscordException as exc:
                logger.warning("No se pudo hacer timeout a %s (%s): %s", member, member.id, exc)

    if cfg.get("lockdown") and not member.guild_permissions.administrator and not is_prefix_help:
        try:
            await message.delete()
            deleted = True
        except discord.DiscordException:
            pass

    save_db(db)

    if not deleted or is_prefix_help:
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
            await send_alert(after.guild.id, f"Se retiro el rol bloqueado {role.mention} a {after.mention}.")
        except discord.DiscordException as exc:
            logger.warning("No se pudo retirar el rol bloqueado: %s", exc)


@bot.event
async def on_command_error(ctx: commands.Context, error: commands.CommandError):
    if hasattr(ctx.command, "on_error"):
        return
    if isinstance(error, commands.CommandNotFound):
        await ctx.send(f"Comando no encontrado. Usa `{HELP_PREFIX}`.")
        return
    logger.exception("Error no controlado en comando prefix", exc_info=error)
    await ctx.send("Ocurrio un error al ejecutar el comando.")


@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    sender = interaction.followup.send if interaction.response.is_done() else interaction.response.send_message
    if isinstance(error, app_commands.MissingPermissions):
        await sender("No tienes permisos para usar este comando.", ephemeral=True)
        return
    logger.exception("Error en slash command", exc_info=error)
    await sender("Ocurrio un error al ejecutar el comando.", ephemeral=True)


@bot.command(name="ghelp")
async def prefix_help(ctx: commands.Context):
    view = HelpCenterView(ctx.guild)
    await ctx.send(embed=build_help_embed("general"), view=view)


@bot.tree.command(name="ghelp", description="Abre la ayuda interactiva del bot Guardian.")
async def slash_help(interaction: discord.Interaction):
    view = HelpCenterView(interaction.guild)
    await interaction.response.send_message(embed=build_help_embed("general"), view=view, ephemeral=True)


@bot.tree.command(name="controlpanel", description="Abre un panel privado con botones rapidos.")
@app_commands.checks.has_permissions(administrator=True)
async def control_panel(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    view = AdminControlView(interaction.guild, interaction.user.id)
    await interaction.response.send_message(
        embed=build_control_panel_embed(interaction.guild),
        view=view,
        ephemeral=True,
    )


@bot.tree.command(name="status", description="Muestra el estado actual del sistema anti-raid.")
async def slash_status(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    await interaction.response.send_message(embed=build_status_embed(interaction.guild), ephemeral=True)


@bot.tree.command(name="dashboard", description="Muestra un dashboard resumido del servidor.")
async def slash_dashboard(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    await interaction.response.send_message(embed=build_dashboard_embed(interaction.guild))


@bot.tree.command(name="lockdown", description="Activa, desactiva o invierte el lockdown.")
@app_commands.describe(mode="Elige si quieres activar, desactivar o invertir el estado actual.")
@app_commands.choices(mode=TOGGLE_CHOICES)
@app_commands.checks.has_permissions(administrator=True)
async def slash_lockdown(interaction: discord.Interaction, mode: app_commands.Choice[str]):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    cfg = get_guild_config(interaction.guild.id)
    new_state = apply_toggle_mode(cfg["lockdown"], mode.value)
    await set_lockdown_state(interaction.guild, new_state, f"Accion manual por {interaction.user}")
    await interaction.response.send_message(
        f"Lockdown {'ACTIVADO' if new_state else 'DESACTIVADO'}."
    )


@bot.tree.command(name="panicmode", description="Activa el modo de panico del servidor.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_panic_mode(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    await trigger_lockdown(interaction.guild)
    await interaction.response.send_message("PANIC MODE activado.")


@bot.tree.command(name="saferole", description="Asigna el rol de verificacion a quien no lo tenga.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_safe_role(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    cfg = get_guild_config(interaction.guild.id)
    verify_role_id = cfg.get("verify_role")
    if not verify_role_id:
        await interaction.response.send_message("No hay rol de verificacion configurado.", ephemeral=True)
        return

    role = interaction.guild.get_role(int(verify_role_id))
    if not role:
        await interaction.response.send_message("El rol configurado ya no existe.", ephemeral=True)
        return

    assigned = 0
    for member in interaction.guild.members:
        if member.bot or role in member.roles:
            continue
        try:
            await member.add_roles(role, reason="Safe role assign")
            assigned += 1
        except discord.DiscordException as exc:
            logger.warning("No se pudo asignar safe role a %s (%s): %s", member, member.id, exc)

    await interaction.response.send_message(f"{assigned} miembros recibieron el rol seguro.")


@bot.tree.command(name="riskscore", description="Calcula el porcentaje de riesgo del servidor.")
async def slash_risk_score(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    cfg = get_guild_config(interaction.guild.id)
    total_members = max(interaction.guild.member_count or 0, 1)
    joins_24h = count_recent_joins(interaction.guild.id, 86400)
    bans_24h = sum(
        1
        for entry in cfg.get("bans_log", [])
        if now_ts() - entry.get("time", 0) < 86400
    )

    risk_joins = (joins_24h / total_members) * 100 * 0.5
    risk_spam = min(cfg.get("spam_incidents", 0), 100) * 0.3
    risk_bans = min(bans_24h * 10, 100) * 0.2
    risk = min(risk_joins + risk_spam + risk_bans, 100)

    color = 0xFF0000 if risk > 75 else 0xFFA500 if risk > 30 else 0x00FF00
    embed = discord.Embed(
        title=f"Risk Score de {interaction.guild.name}",
        description=f"{risk:.1f}%",
        color=color,
    )
    embed.add_field(name="Uniones recientes (24h)", value=str(joins_24h), inline=True)
    embed.add_field(name="Incidentes de spam", value=str(cfg.get("spam_incidents", 0)), inline=True)
    embed.add_field(name="Baneos recientes (24h)", value=str(bans_24h), inline=True)
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="patternban", description="Agrega un patron regex de baneo por contenido.")
@app_commands.describe(pattern="Regex a detectar en mensajes. Ejemplo: (free nitro|raid link)")
@app_commands.checks.has_permissions(administrator=True)
async def slash_pattern_ban(interaction: discord.Interaction, pattern: str):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    try:
        re.compile(pattern)
    except re.error as exc:
        await interaction.response.send_message(f"Regex invalida: {exc}", ephemeral=True)
        return

    cfg = get_guild_config(interaction.guild.id)
    if pattern not in cfg["ban_patterns"]:
        cfg["ban_patterns"].append(pattern)
        save_db(db)
    await interaction.response.send_message(f"Patron `{pattern}` agregado.")


@bot.tree.command(name="linkfilter", description="Activa o desactiva el filtro de enlaces.")
@app_commands.describe(mode="Elige activar, desactivar o invertir.")
@app_commands.choices(mode=TOGGLE_CHOICES)
@app_commands.checks.has_permissions(administrator=True)
async def slash_link_filter(interaction: discord.Interaction, mode: app_commands.Choice[str]):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg["link_filter"] = apply_toggle_mode(cfg["link_filter"], mode.value)
    save_db(db)
    await interaction.response.send_message(
        f"Filtro de enlaces: {'ACTIVADO' if cfg['link_filter'] else 'DESACTIVADO'}"
    )


@bot.tree.command(name="mentionspam", description="Cambia el limite de menciones por mensaje.")
@app_commands.describe(limit="Cantidad maxima de menciones permitidas.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_mention_limit(interaction: discord.Interaction, limit: app_commands.Range[int, 1, 50]):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg["mention_limit"] = limit
    save_db(db)
    await interaction.response.send_message(f"Limite de menciones actualizado a {limit}.")


@bot.tree.command(name="emojispam", description="Cambia el limite de emojis personalizados por mensaje.")
@app_commands.describe(limit="Cantidad maxima de emojis personalizados permitidos.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_emoji_limit(interaction: discord.Interaction, limit: app_commands.Range[int, 1, 50]):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg["emoji_limit"] = limit
    save_db(db)
    await interaction.response.send_message(f"Limite de emojis actualizado a {limit}.")


@bot.tree.command(name="nitroprotect", description="Activa o desactiva la proteccion de enlaces Nitro.")
@app_commands.describe(mode="Elige activar, desactivar o invertir.")
@app_commands.choices(mode=TOGGLE_CHOICES)
@app_commands.checks.has_permissions(administrator=True)
async def slash_nitro_protect(interaction: discord.Interaction, mode: app_commands.Choice[str]):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg["nitro_links"] = apply_toggle_mode(cfg["nitro_links"], mode.value)
    save_db(db)
    await interaction.response.send_message(
        f"Proteccion Nitro: {'ACTIVADA' if cfg['nitro_links'] else 'DESACTIVADA'}"
    )


@bot.tree.command(name="invitespam", description="Cambia el limite de invitaciones por mensaje.")
@app_commands.describe(limit="Cantidad maxima de invitaciones permitidas antes de marcar spam.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_invite_limit(interaction: discord.Interaction, limit: app_commands.Range[int, 1, 20]):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg["invite_spam_limit"] = limit
    save_db(db)
    await interaction.response.send_message(f"Limite de invitaciones actualizado a {limit}.")


@bot.tree.command(name="setverifyrole", description="Configura el rol de verificacion automatica.")
@app_commands.describe(role="Rol que se dara a nuevos miembros.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_set_verify_role(interaction: discord.Interaction, role: discord.Role):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg["verify_role"] = str(role.id)
    save_db(db)
    await interaction.response.send_message(f"Rol de verificacion configurado: {role.mention}")


@bot.tree.command(name="setlogchannel", description="Configura el canal donde se enviaran los logs.")
@app_commands.describe(channel="Canal de texto para logs.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_set_log_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg["log_channel"] = str(channel.id)
    save_db(db)
    await interaction.response.send_message(f"Canal de logs configurado: {channel.mention}")


@bot.tree.command(name="setalertchannel", description="Configura el canal donde se enviaran las alertas.")
@app_commands.describe(channel="Canal de texto para alertas.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_set_alert_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg["alert_channel"] = str(channel.id)
    save_db(db)
    await interaction.response.send_message(f"Canal de alertas configurado: {channel.mention}")


@bot.tree.command(name="blacklist", description="Agrega un miembro a la blacklist.")
@app_commands.describe(member="Miembro que quieres bloquear.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_blacklist_member(interaction: discord.Interaction, member: discord.Member):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    member_id = str(member.id)
    if member_id not in cfg["blacklists"]:
        cfg["blacklists"].append(member_id)
        save_db(db)
    await interaction.response.send_message(f"{member.mention} agregado a la blacklist.")


@bot.tree.command(name="blacklistrole", description="Agrega un rol a la blacklist.")
@app_commands.describe(role="Rol que quieres bloquear.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_blacklist_role(interaction: discord.Interaction, role: discord.Role):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    role_id = str(role.id)
    if role_id not in cfg["blacklists"]:
        cfg["blacklists"].append(role_id)
        save_db(db)
    await interaction.response.send_message(f"Rol {role.mention} agregado a la blacklist.")


@bot.tree.command(name="whitelist", description="Agrega un miembro a la whitelist.")
@app_commands.describe(member="Miembro que quieres proteger.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_whitelist(interaction: discord.Interaction, member: discord.Member):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    member_id = str(member.id)
    if member_id not in cfg["whitelist"]:
        cfg["whitelist"].append(member_id)
        save_db(db)
    await interaction.response.send_message(f"{member.mention} agregado a la whitelist.")


@bot.tree.command(name="whitelistrole", description="Agrega a la whitelist a todos los miembros de un rol.")
@app_commands.describe(role="Rol cuyos miembros seran protegidos.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_whitelist_role(interaction: discord.Interaction, role: discord.Role):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    added = 0
    for member in role.members:
        member_id = str(member.id)
        if member_id not in cfg["whitelist"]:
            cfg["whitelist"].append(member_id)
            added += 1
    save_db(db)
    await interaction.response.send_message(f"{added} miembros del rol {role.mention} agregados a la whitelist.")


@bot.tree.command(name="banwave", description="Banea a todos los miembros de un rol.")
@app_commands.describe(role="Rol cuyos miembros seran baneados.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_ban_wave(interaction: discord.Interaction, role: discord.Role):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    async def callback(confirm_interaction: discord.Interaction, confirmed: bool):
        if not confirmed:
            await confirm_interaction.response.edit_message(content="Accion cancelada.", embed=None, view=None)
            return

        cfg = get_guild_config(interaction.guild.id)
        banned_count = 0
        for member in role.members:
            if bot.user and member.id == bot.user.id:
                continue
            if member_is_whitelisted(member, cfg):
                continue
            try:
                await interaction.guild.ban(member, reason="Banwave anti-raid")
                cfg["bans_log"].append(
                    {"user": str(member.id), "time": now_ts(), "reason": "Banwave"}
                )
                banned_count += 1
            except discord.DiscordException as exc:
                logger.warning("Banwave fallo con %s (%s): %s", member, member.id, exc)

        save_db(db)
        await confirm_interaction.response.edit_message(
            content=f"{banned_count} miembros del rol {role.mention} fueron baneados.",
            embed=None,
            view=None,
        )

    embed = discord.Embed(
        title="Confirmar banwave",
        description=f"Vas a banear a {len(role.members)} miembros de {role.mention}.",
        color=0xFF0000,
    )
    await interaction.response.send_message(
        embed=embed,
        view=Confirm(interaction.user.id, callback),
        ephemeral=True,
    )


@bot.tree.command(name="softban", description="Ban y unban para limpiar mensajes recientes.")
@app_commands.describe(member="Miembro al que quieres aplicar softban.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_soft_ban(interaction: discord.Interaction, member: discord.Member):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    if member_is_whitelisted(member, cfg):
        await interaction.response.send_message("Ese miembro esta en la whitelist.", ephemeral=True)
        return
    try:
        await interaction.guild.ban(
            member,
            reason="Softban anti-raid",
            delete_message_seconds=7 * 24 * 60 * 60,
        )
        await interaction.guild.unban(member, reason="Softban anti-raid")
        cfg["bans_log"].append({"user": str(member.id), "time": now_ts(), "reason": "Softban"})
        save_db(db)
        await interaction.response.send_message(f"{member.mention} ha sido softbaneado.")
    except discord.DiscordException as exc:
        await interaction.response.send_message(f"No se pudo softbanear a {member.mention}: {exc}", ephemeral=True)


@bot.tree.command(name="usertrack", description="Muestra actividad basica de un usuario.")
@app_commands.describe(member="Miembro a consultar. Si no se indica, te muestra a ti.")
async def slash_user_track(interaction: discord.Interaction, member: Optional[discord.Member] = None):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    target = member or interaction.user
    if not isinstance(target, discord.Member):
        await interaction.response.send_message("No pude resolver al miembro.", ephemeral=True)
        return
    await interaction.response.send_message(embed=build_member_stats_embed(interaction.guild, target))


@bot.tree.command(name="raidstats", description="Muestra estadisticas generales anti-raid.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_raid_stats(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    await interaction.response.send_message(embed=build_stats_embed(interaction.guild.id))


@bot.tree.command(name="top_spammers", description="Lista los usuarios con mas mensajes registrados.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_top_spammers(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    guild_stats = cfg.get("user_stats", {})
    if not guild_stats:
        await interaction.response.send_message("No hay estadisticas todavia.", ephemeral=True)
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
            member = interaction.guild.get_member(int(user_id))
            name = member.display_name if member else f"Usuario {user_id}"
            lines.append(f"{offset}. **{name}** - {stats.get('msgs', 0)} mensajes")
        pages.append("\n".join(lines))

    view = Pagination("Top spammers", pages, interaction.user.id)
    await interaction.response.send_message(embed=view.build_embed(), view=view, ephemeral=True)


@bot.tree.command(name="recent_joins", description="Lista las uniones recientes registradas.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_recent_joins(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    entries = list(recent_joins[str(interaction.guild.id)])
    if not entries:
        await interaction.response.send_message("No hay uniones recientes.", ephemeral=True)
        return

    pages = []
    for start in range(0, len(entries), 10):
        lines = []
        for entry in entries[start : start + 10]:
            member = interaction.guild.get_member(entry["user_id"])
            if member:
                lines.append(member.mention)
            else:
                lines.append(f"Usuario {entry['user_id']}")
        pages.append("\n".join(lines))

    view = Pagination("Uniones recientes", pages, interaction.user.id)
    await interaction.response.send_message(embed=view.build_embed(), view=view, ephemeral=True)


@bot.tree.command(name="lockchannel", description="Bloquea un canal de texto.")
@app_commands.describe(channel="Canal que quieres bloquear.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_lock_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg["channel_locks"][str(channel.id)] = True
    save_db(db)
    try:
        overwrite = channel.overwrites_for(interaction.guild.default_role)
        overwrite.send_messages = False
        await channel.set_permissions(interaction.guild.default_role, overwrite=overwrite)
        await interaction.response.send_message(f"{channel.mention} bloqueado.")
    except discord.DiscordException as exc:
        await interaction.response.send_message(f"No se pudo bloquear el canal: {exc}", ephemeral=True)


@bot.tree.command(name="unlockchannel", description="Desbloquea un canal de texto.")
@app_commands.describe(channel="Canal que quieres desbloquear.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_unlock_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg["channel_locks"].pop(str(channel.id), None)
    save_db(db)
    try:
        overwrite = channel.overwrites_for(interaction.guild.default_role)
        overwrite.send_messages = None
        await channel.set_permissions(interaction.guild.default_role, overwrite=overwrite)
        await interaction.response.send_message(f"{channel.mention} desbloqueado.")
    except discord.DiscordException as exc:
        await interaction.response.send_message(f"No se pudo desbloquear el canal: {exc}", ephemeral=True)


@bot.tree.command(name="rolelock", description="Bloquea la asignacion de un rol.")
@app_commands.describe(role="Rol cuya asignacion se quiere bloquear.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_role_lock(interaction: discord.Interaction, role: discord.Role):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg["role_locks"][str(role.id)] = True
    save_db(db)
    await interaction.response.send_message(f"Rol {role.mention} bloqueado para futuras asignaciones.")


@bot.tree.command(name="unlockrole", description="Quita el bloqueo de un rol.")
@app_commands.describe(role="Rol cuyo bloqueo quieres eliminar.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_role_unlock(interaction: discord.Interaction, role: discord.Role):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg["role_locks"].pop(str(role.id), None)
    save_db(db)
    await interaction.response.send_message(f"Rol {role.mention} desbloqueado.")


@bot.tree.command(name="captcha", description="Activa o desactiva el captcha para nuevos miembros.")
@app_commands.describe(mode="Elige activar, desactivar o invertir.")
@app_commands.choices(mode=TOGGLE_CHOICES)
@app_commands.checks.has_permissions(administrator=True)
async def slash_captcha(interaction: discord.Interaction, mode: app_commands.Choice[str]):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg["captcha_enabled"] = apply_toggle_mode(cfg["captcha_enabled"], mode.value)
    save_db(db)
    await interaction.response.send_message(
        f"Captcha: {'ACTIVADO' if cfg['captcha_enabled'] else 'DESACTIVADO'}"
    )


@bot.tree.command(name="vpncheck", description="Evalua el riesgo de una cuenta por antiguedad.")
@app_commands.describe(member="Miembro que quieres revisar.")
async def slash_vpn_check(interaction: discord.Interaction, member: discord.Member):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    days_old = (discord.utils.utcnow() - member.created_at).days
    risk = "ALTO RIESGO" if days_old < 7 else "BAJO RIESGO"
    embed = discord.Embed(
        title=f"Revision de cuenta: {member.display_name}",
        description=f"Antiguedad: {days_old} dias\nRiesgo estimado: {risk}",
        color=0x00BFFF,
    )
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="masskick", description="Expulsa cuentas creadas hace menos de 7 dias.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_mass_kick(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    async def callback(confirm_interaction: discord.Interaction, confirmed: bool):
        if not confirmed:
            await confirm_interaction.response.edit_message(content="Accion cancelada.", embed=None, view=None)
            return

        kicked_count = 0
        seven_days_ago = discord.utils.utcnow() - timedelta(days=7)
        for member in interaction.guild.members:
            if member.bot or (bot.user and member.id == bot.user.id):
                continue
            if member.created_at < seven_days_ago:
                continue
            try:
                await member.kick(reason="Cuenta nueva sospechosa (<7 dias)")
                kicked_count += 1
            except discord.DiscordException as exc:
                logger.warning("Masskick fallo con %s (%s): %s", member, member.id, exc)

        await confirm_interaction.response.edit_message(
            content=f"{kicked_count} cuentas nuevas expulsadas.",
            embed=None,
            view=None,
        )

    embed = discord.Embed(
        title="Confirmar masskick",
        description="Esto expulsara cuentas creadas hace menos de 7 dias.",
        color=0xFF0000,
    )
    await interaction.response.send_message(
        embed=embed,
        view=Confirm(interaction.user.id, callback),
        ephemeral=True,
    )


@bot.tree.command(name="configdump", description="Muestra la configuracion actual del servidor.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_config_dump(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    cfg = get_guild_config(interaction.guild.id)
    lines = [f"`{key}` = `{truncate(str(value), 180)}`" for key, value in cfg.items()]
    pages = ["\n".join(lines[i : i + 8]) for i in range(0, len(lines), 8)]
    view = Pagination("Configuracion del servidor", pages, interaction.user.id)
    await interaction.response.send_message(embed=view.build_embed(), view=view, ephemeral=True)


@bot.tree.command(name="config", description="Edita una clave segura de configuracion.")
@app_commands.describe(
    key="Clave segura a editar.",
    value="Nuevo valor. Usa numeros para limites.",
)
@app_commands.choices(key=CONFIG_KEY_CHOICES)
@app_commands.checks.has_permissions(administrator=True)
async def slash_config_edit(
    interaction: discord.Interaction,
    key: app_commands.Choice[str],
    value: str,
):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    cfg = get_guild_config(interaction.guild.id)
    caster = CONFIG_EDITABLE_KEYS[key.value]
    parsed = load_jsonish(value)
    try:
        cfg[key.value] = caster(parsed)
    except (TypeError, ValueError):
        await interaction.response.send_message(
            f"El valor `{value}` no es valido para `{key.value}`.",
            ephemeral=True,
        )
        return

    save_db(db)
    await interaction.response.send_message(f"Configuracion actualizada: `{key.value}` = `{cfg[key.value]}`")


@bot.tree.command(name="resetdb", description="Restaura la configuracion por defecto del servidor.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_reset_db(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    async def callback(confirm_interaction: discord.Interaction, confirmed: bool):
        if not confirmed:
            await confirm_interaction.response.edit_message(content="Accion cancelada.", embed=None, view=None)
            return

        db["guilds"][str(interaction.guild.id)] = copy.deepcopy(DEFAULT_GUILD_CONFIG)
        save_db(db)
        await confirm_interaction.response.edit_message(
            content="Configuracion del servidor restablecida.",
            embed=None,
            view=None,
        )

    embed = discord.Embed(
        title="Confirmar reset",
        description="Esto reseteara la configuracion del servidor a los valores por defecto.",
        color=0xFF0000,
    )
    await interaction.response.send_message(
        embed=embed,
        view=Confirm(interaction.user.id, callback),
        ephemeral=True,
    )


@bot.tree.command(name="backupdb", description="Exporta la configuracion del servidor a un JSON.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_backup_db(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    config = get_guild_config(interaction.guild.id)
    payload = json.dumps(config, indent=2, ensure_ascii=False).encode("utf-8")
    file = discord.File(io.BytesIO(payload), filename=f"{interaction.guild.id}_backup_{int(now_ts())}.json")
    await interaction.response.send_message("Backup generado:", file=file, ephemeral=True)


@bot.tree.command(name="webhooklogs", description="Configura o elimina el webhook de logs.")
@app_commands.describe(
    action="Elige si quieres configurar o eliminar el webhook.",
    url="URL del webhook si eliges configurar.",
)
@app_commands.choices(action=WEBHOOK_ACTION_CHOICES)
@app_commands.checks.has_permissions(administrator=True)
async def slash_webhook_logs(
    interaction: discord.Interaction,
    action: app_commands.Choice[str],
    url: Optional[str] = None,
):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    cfg = get_guild_config(interaction.guild.id)
    if action.value == "set":
        if not url:
            await interaction.response.send_message("Debes indicar una URL para configurar el webhook.", ephemeral=True)
            return
        if "discord.com/api/webhooks/" not in url and "discordapp.com/api/webhooks/" not in url:
            await interaction.response.send_message("URL de webhook invalida.", ephemeral=True)
            return
        cfg["webhook_logs"] = url
        save_db(db)
        await interaction.response.send_message("Webhook de logs configurado.")
        return

    cfg["webhook_logs"] = None
    save_db(db)
    await interaction.response.send_message("Webhook de logs eliminado.")


@bot.tree.command(name="alerttest", description="Envia una alerta de prueba al canal configurado.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_alert_test(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    await send_alert(interaction.guild.id, "Mensaje de prueba de alerta.")
    await interaction.response.send_message("Prueba de alerta enviada.")


@bot.tree.command(name="lockdownmode", description="Define el modo de lockdown: soft o hard.")
@app_commands.describe(mode="Selecciona el modo de lockdown.")
@app_commands.choices(mode=LOCKDOWN_MODE_CHOICES)
@app_commands.checks.has_permissions(administrator=True)
async def slash_lockdown_mode(interaction: discord.Interaction, mode: app_commands.Choice[str]):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg["lockdown_mode"] = mode.value
    save_db(db)
    await interaction.response.send_message(f"Modo de lockdown actualizado a `{mode.value}`.")


@bot.tree.command(name="mutewave", description="Aplica timeout a los usuarios unidos recientemente.")
@app_commands.describe(duration="Duracion del timeout en minutos.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_mute_wave(interaction: discord.Interaction, duration: app_commands.Range[int, 1, 1440]):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    if not bot_has_perms(interaction.guild, ["moderate_members"]):
        await interaction.response.send_message("El bot no tiene permiso `moderate_members`.", ephemeral=True)
        return

    muted = 0
    entries = list(recent_joins[str(interaction.guild.id)])[-100:]
    for entry in entries:
        member = interaction.guild.get_member(entry["user_id"])
        if not member or member.bot or member.is_timed_out():
            continue
        try:
            await member.timeout(
                discord.utils.utcnow() + timedelta(minutes=duration),
                reason="Mute wave por uniones recientes",
            )
            muted += 1
        except discord.DiscordException as exc:
            logger.warning("No se pudo mutear a %s (%s): %s", member, member.id, exc)

    await interaction.response.send_message(f"{muted} miembros muteados por {duration} minutos.")


@bot.tree.command(name="unmuteall", description="Quita todos los timeouts activos del servidor.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_unmute_all(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    if not bot_has_perms(interaction.guild, ["moderate_members"]):
        await interaction.response.send_message("El bot no tiene permiso `moderate_members`.", ephemeral=True)
        return

    unmuted = 0
    for member in interaction.guild.members:
        if not member.is_timed_out():
            continue
        try:
            await member.timeout(None, reason="Desmuteo general")
            unmuted += 1
        except discord.DiscordException as exc:
            logger.warning("No se pudo desmutear a %s (%s): %s", member, member.id, exc)

    await interaction.response.send_message(f"{unmuted} miembros desmuteados.")


@bot.tree.command(name="kickrecent", description="Expulsa a los ultimos miembros que se unieron.")
@app_commands.describe(amount="Cantidad de usuarios recientes a expulsar.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_kick_recent(interaction: discord.Interaction, amount: app_commands.Range[int, 1, 100] = 10):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    if not bot_has_perms(interaction.guild, ["kick_members"]):
        await interaction.response.send_message("El bot no tiene permiso `kick_members`.", ephemeral=True)
        return

    kicked = 0
    cfg = get_guild_config(interaction.guild.id)
    entries = list(recent_joins[str(interaction.guild.id)])[-amount:]
    for entry in entries:
        member = interaction.guild.get_member(entry["user_id"])
        if not member or member.bot or member_is_whitelisted(member, cfg):
            continue
        try:
            await member.kick(reason="Kick por unirse recientemente")
            kicked += 1
        except discord.DiscordException as exc:
            logger.warning("No se pudo expulsar a %s (%s): %s", member, member.id, exc)

    await interaction.response.send_message(f"{kicked} de los ultimos {amount} miembros fueron expulsados.")


@bot.tree.command(name="banspammer", description="Banea a un usuario si supera el umbral de spam.")
@app_commands.describe(member="Miembro a evaluar.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_ban_spammer(interaction: discord.Interaction, member: discord.Member):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    cfg = get_guild_config(interaction.guild.id)
    stats = cfg.get("user_stats", {}).get(str(member.id), {"msgs": 0})
    spam_threshold = cfg.get("threshold_msgs", 8) * 2
    days_old = (discord.utils.utcnow() - member.created_at).days
    age_factor = 0.5 if days_old < 7 else 1.0

    if stats["msgs"] * age_factor <= spam_threshold:
        await interaction.response.send_message(
            f"{member.mention} no cumple criterios de ban. Mensajes: {stats['msgs']}, edad: {days_old} dias.",
            ephemeral=True,
        )
        return

    if not bot_has_perms(interaction.guild, ["ban_members"]):
        await interaction.response.send_message("El bot no tiene permiso `ban_members`.", ephemeral=True)
        return

    try:
        await interaction.guild.ban(member, reason="Spammer activo")
        cfg["bans_log"].append({"user": str(member.id), "time": now_ts(), "reason": "Spammer activo"})
        save_db(db)
        await interaction.response.send_message(f"{member.mention} baneado por spam activo.")
    except discord.DiscordException as exc:
        await interaction.response.send_message(f"No se pudo banear a {member.mention}: {exc}", ephemeral=True)


@bot.tree.command(name="warns", description="Muestra las advertencias de un miembro.")
@app_commands.describe(member="Miembro a consultar. Si no se indica, te muestra a ti.")
async def slash_warns(interaction: discord.Interaction, member: Optional[discord.Member] = None):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    target = member or interaction.user
    if not isinstance(target, discord.Member):
        await interaction.response.send_message("No pude resolver al miembro.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    warns = cfg.get("warns", {}).get(str(target.id), [])
    await interaction.response.send_message(embed=build_warns_embed(target, warns), ephemeral=True)


@bot.tree.command(name="strikes", description="Muestra los strikes de un miembro.")
@app_commands.describe(member="Miembro a consultar. Si no se indica, te muestra a ti.")
async def slash_strikes(interaction: discord.Interaction, member: Optional[discord.Member] = None):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    target = member or interaction.user
    if not isinstance(target, discord.Member):
        await interaction.response.send_message("No pude resolver al miembro.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    strikes = cfg.get("strikes", {}).get(str(target.id), [])
    await interaction.response.send_message(embed=build_strikes_embed(target, strikes), ephemeral=True)


@bot.tree.command(name="forgive", description="Borra warns y strikes de un miembro.")
@app_commands.describe(member="Miembro al que quieres limpiar el historial.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_forgive(interaction: discord.Interaction, member: discord.Member):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    cfg = get_guild_config(interaction.guild.id)
    cfg.get("warns", {}).pop(str(member.id), None)
    cfg.get("strikes", {}).pop(str(member.id), None)
    save_db(db)
    await interaction.response.send_message(f"{member.mention} ha sido perdonado.")


@bot.tree.command(name="auditlog", description="Muestra un resumen de auditoria del servidor.")
async def slash_audit_log(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return

    cfg = get_guild_config(interaction.guild.id)
    bans_count = len(cfg.get("bans_log", []))
    kicks_count = 0
    if bot_has_perms(interaction.guild, ["view_audit_log"]):
        try:
            async for _entry in interaction.guild.audit_logs(action=discord.AuditLogAction.kick, limit=100):
                kicks_count += 1
        except discord.DiscordException as exc:
            logger.warning("No se pudo leer audit log: %s", exc)

    embed = discord.Embed(title="Resumen de auditoria", color=0x8A2BE2)
    embed.add_field(name="Baneos registrados", value=str(bans_count), inline=True)
    embed.add_field(name="Kicks recientes", value=str(kicks_count), inline=True)
    embed.add_field(name="Incidentes de spam", value=str(cfg.get("spam_incidents", 0)), inline=True)
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="membercount", description="Muestra el conteo de miembros y altas recientes.")
async def slash_member_count(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    await interaction.response.send_message(embed=build_membercount_embed(interaction.guild))


@bot.tree.command(name="botperms", description="Muestra los permisos actuales del bot.")
async def slash_bot_perms(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("Este comando solo funciona en servidores.", ephemeral=True)
        return
    await interaction.response.send_message(embed=build_bot_permissions_embed(interaction.guild), ephemeral=True)


@bot.tree.command(name="sync", description="Sincroniza los comandos slash del bot.")
@app_commands.checks.has_permissions(administrator=True)
async def slash_sync(interaction: discord.Interaction):
    try:
        synced = await bot.tree.sync()
        await interaction.response.send_message(f"Se sincronizaron {len(synced)} comandos slash.")
    except discord.HTTPException as exc:
        await interaction.response.send_message(f"No se pudieron sincronizar los comandos slash: {exc}", ephemeral=True)


if __name__ == "__main__":
    bot.run(TOKEN)
