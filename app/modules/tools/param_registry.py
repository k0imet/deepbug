"""
ParamRegistry — unified parameter name corpus for all scanners.

Every scanner that needs to know WHAT parameter names to probe (redirect,
SSRF, IDOR, SQLi, XSS, RCE, file-read, SSTI) pulls from this single source.

Derived from the 11,304-report disclosure catalog, gf-patterns, and real
live-target misses (freevisit.ru `g=`, Juice Shop, BitOasis, Redbull).
"""

from typing import Dict, List, Set, Optional

_PARAMS = {
    "redirect": [
        "g", "r", "l", "u", "url", "url2", "uri", "to", "go", "next",
        "ref", "return", "returnUrl", "returnTo", "return_url", "return_to",
        "redirect", "redirectUrl", "redirectTo", "redirect_uri", "redirect_url",
        "forward", "forwardUrl", "destination", "dest", "target", "origin",
        "callback", "cb", "redirectUrl", "rurl", "p", "goto", "continue",
        "prev", "referer", "referrer", "back", "backUrl", "back_to",
        "link", "jump", "jumpUrl", "domain", "site", "path",
        "out", "view", "page", "dir", "loc", "location",
        "successUrl", "errorUrl", "cancelUrl", "fallback", "urlRedirect",
        "navigate", "navigateTo", "open", "openUrl", "linkUrl",
        "sso_redirect", "post_logout_redirect_uri", "logout_redirect",
        "loginRedirect", "afterLogin", "home", "redirect_url",
        "redirectToUrl", "redirect_url_after_login", "RelayState",
        "SAMLRequest", "SAMLart", "openid.return_to", "oauth_callback",
        "oauth_redirect", "oidc_redirect_uri", "redirectURI",
    ],
    "ssrf": [
        "url", "uri", "link", "src", "source", "target", "dest",
        "destination", "path", "domain", "host", "referer", "site",
        "proxy", "proxyUrl", "api", "endpoint", "callback", "webhook",
        "hook", "notify_url", "notification_url", "ping_url", "ping",
        "import", "feed", "rss", "fetch", "load", "download",
        "image", "img", "img_url", "image_url", "avatar", "avatar_url",
        "photo", "photo_url", "picture", "pic", "icon", "logo",
        "thumbnail", "thumb", "preview", "media", "file", "files",
        "upload", "asset", "assets", "resource", "resources",
        "xml", "json", "xmlUrl", "jsonUrl", "dataUrl", "resourceUrl",
        "serviceUrl", "wsdl", "soap", "rest", "graphql",
        "webhookUrl", "callbackUrl", "returnUrl", "redirectUrl",
        "url_", "url__", "nextUrl", "s3_url", "bucket_url", "cdn_url",
        "remoteUrl", "externalUrl", "fetchUrl", "loadUrl",
        "fontUrl", "cssUrl", "jsUrl", "scriptUrl", "stylesheetUrl",
        "apiUrl", "baseUrl", "graphqlUrl", "wsUrl", "wssUrl",
        "videoUrl", "audioUrl", "pdfUrl", "documentUrl",
        "templateUrl", "includeUrl", "renderUrl", "render", "pdf",
        "html", "convert", "thumbnailUrl", "previewUrl", "og_image",
        "og_url", "twitter_image", "tracking", "pixel", "beacon",
        "import_url", "sync_url", "mirror_url", "replicate_url",
    ],
    "idor": [
        "id", "uid", "uuid", "guid", "pk", "key", "user", "userId",
        "user_id", "uid2", "account", "accountId", "account_id",
        "customer", "customerId", "customer_id", "client", "clientId",
        "order", "orderId", "order_id", "payment", "paymentId",
        "invoice", "invoiceId", "transaction", "transactionId",
        "profile", "profileId", "member", "memberId", "admin",
        "adminId", "author", "authorId", "owner", "ownerId",
        "recipient", "recipientId", "sender", "senderId",
        "report", "reportId", "request", "requestId", "ticket",
        "ticketId", "task", "taskId", "project", "projectId",
        "document", "documentId", "file", "fileId", "photo",
        "photoId", "image", "imageId", "album", "albumId",
        "comment", "commentId", "post", "postId", "thread",
        "threadId", "message", "messageId", "conversation",
        "conversationId", "chat", "chatId", "room", "roomId",
        "group", "groupId", "team", "teamId", "org", "orgId",
        "organization", "organizationId", "company", "companyId",
        "workspace", "workspaceId", "board", "boardId", "card",
        "cardId", "list", "listId", "note", "noteId", "page",
        "pageId", "draft", "draftId", "email", "mail", "emailId",
        "username", "login", "handle", "slack", "phone", "number",
        "iban", "account_number", "accountNumber", "cc", "card",
        "cardId", "subscription", "subscriptionId", "plan", "planId",
        "item", "itemId", "product", "productId", "sku", "variant",
        "variantId", "store", "storeId", "shop", "shopId",
        "repository", "repo", "repoId", "commit", "commitId",
        "branch", "tag", "release", "build", "buildId", "pipeline",
        "pipelineId", "job", "jobId", "run", "runId", "deploy",
        "deployId", "session", "sessionId", "token", "tokenId",
        "role", "roleId", "permission", "permissionId",
        "address", "addressId", "location", "locationId",
        "device", "deviceId", "app", "appId", "service", "serviceId",
        "integration", "integrationId", "connection", "connectionId",
        "webhook", "webhookId", "api", "apiKey", "api_key",
        "secret", "credential", "credentialId", "cert", "certId",
        "batch", "batchId", "export", "exportId", "import",
        "importId", "log", "logId", "event", "eventId",
        "alert", "alertId", "notification", "notificationId",
        "survey", "surveyId", "form", "formId", "quiz", "quizId",
        "course", "courseId", "lesson", "lessonId", "module",
        "moduleId", "grade", "gradeId", "submission", "submissionId",
        "assignment", "assignmentId", "exam", "examId",
        "booking", "bookingId", "reservation", "reservationId",
        "appointment", "appointmentId", "schedule", "scheduleId",
        "flight", "flightId", "trip", "tripId", "route", "routeId",
        "shipment", "shipmentId", "tracking", "trackingId",
        "policy", "policyId", "claim", "claimId", "case", "caseId",
        "contract", "contractId", "agreement", "agreementId",
        "quote", "quoteId", "estimate", "estimateId", "proposal",
        "proposalId", "template", "templateId", "version", "versionId",
        "revision", "revisionId", "snapshot", "snapshotId",
        "username", "screen_name", "display_name", "nickname",
        "email", "phone", "phone_number", "mobile", "SSN", "tax_id",
        "passport", "license", "licenseId", "registration", "regId",
    ],
    "sqli": [
        "id", "q", "query", "search", "s", "keyword", "keywords",
        "term", "terms", "filter", "filters", "sort", "order",
        "orderBy", "order_by", "sortBy", "sort_by", "dir", "direction",
        "page", "limit", "offset", "skip", "take", "top", "count",
        "category", "cat", "type", "kind", "status", "state",
        "user", "username", "name", "email", "login", "password",
        "key", "api_key", "token", "auth", "session", "hash",
        "id", "item", "product", "sku", "code", "ref", "reference",
        "group", "groupBy", "group_by", "field", "fields", "column",
        "columns", "select", "where", "from", "join", "having",
        "table", "tables", "schema", "db", "database",
        "action", "cmd", "command", "exec", "execute", "run",
        "lang", "language", "locale", "country", "region",
        "date", "time", "year", "month", "day", "week",
        "start", "end", "from", "to", "since", "until",
        "min", "max", "min_price", "max_price", "price", "amount",
        "lat", "lng", "lon", "latitude", "longitude", "zoom",
        "format", "output", "type", "mode", "view", "layout",
        "callback", "callbackFunction", "jsonp",
        "param", "params", "args", "arg", "input", "value",
        "data", "body", "payload", "request", "response",
        "debug", "test", "preview", "draft", "raw",
        "admin", "root", "super", "backdoor",
    ],
    "xss": [
        "q", "s", "search", "query", "keyword", "keywords",
        "term", "terms", "text", "body", "content", "message",
        "msg", "description", "desc", "summary", "title", "name",
        "comment", "review", "feedback", "note", "notes",
        "subject", "topic", "about", "bio", "biography",
        "first_name", "last_name", "full_name", "display_name",
        "username", "nickname", "handle", "email", "address",
        "city", "state", "country", "location", "url", "website",
        "link", "href", "src", "value", "data", "html",
        "markdown", "rich", "editor", "wysiwyg", "bbcode",
        "redirect", "redirectUrl", "callback", "cb", "return",
        "returnUrl", "returnTo", "next", "goto", "target",
        "error", "errorMsg", "error_message", "warning", "info",
        "success", "flash", "alert", "notice", "toast",
        "file", "filename", "path", "dir", "folder",
        "color", "colour", "bg", "background", "theme", "style",
        "template", "tpl", "layout", "skin", "view",
        "lang", "language", "locale", "currency", "format",
        "profile", "avatar", "image", "photo", "picture", "icon",
        "logo", "banner", "header", "footer", "tag", "label",
        "category", "type", "class", "id", "ref", "source",
        "utm_source", "utm_medium", "utm_campaign", "utm_term",
        "utm_content", "affiliate", "partner", "referral", "ref",
        "tracking", "trackingId", "pixel", "pixelId",
        "custom", "customField", "custom_field", "meta", "metadata",
        "json", "xml", "csv", "export", "import", "upload",
        "preview", "preview_html", "render", "rendered",
        "sanitized", "sanitized_html", "stripped", "escaped",
        "raw", "raw_html", "unsafe", "trusted", "untrusted",
    ],
    "rce": [
        "cmd", "command", "exec", "execute", "run", "action",
        "func", "function", "method", "call", "invoke",
        "script", "code", "eval", "expression", "expr",
        "template", "tpl", "view", "render", "renderer",
        "file", "path", "filename", "dir", "directory",
        "include", "require", "import", "load", "require_once",
        "page", "module", "component", "controller", "model",
        "class", "object", "instance", "constructor",
        "lang", "language", "locale", "i18n", "translation",
        "format", "output", "input", "type", "mode",
        "debug", "test", "preview", "sandbox", "playground",
        "shell", "bash", "sh", "terminal", "console",
        "git", "svn", "hg", "repo", "repository",
        "php", "python", "ruby", "perl", "node", "java",
        "binary", "bin", "exe", "dll", "so", "lib",
        "image", "convert", "ffmpeg", "imagemagick", "graphicsmagick",
        "pdf", "doc", "xls", "csv", "xml", "json",
        "zip", "tar", "gz", "archive", "compress",
        "backup", "restore", "migrate", "seed", "fixture",
        "cron", "job", "task", "worker", "queue",
        "env", "environment", "config", "settings", "options",
        "host", "port", "ip", "domain", "url",
        "proxy", "socks", "tunnel", "forward", "relay",
        "upload", "download", "fetch", "pull", "push",
        "install", "update", "upgrade", "patch", "rollback",
        "start", "stop", "restart", "reload", "status",
        "health", "check", "ping", "monitor", "watch",
        "cache", "clear", "flush", "reset", "purge",
        "log", "logs", "trace", "profile", "dump",
        "seed", "generate", "build", "compile", "transpile",
        "pack", "bundle", "minify", "uglify", "optimize",
    ],
    "lfi": [
        "file", "path", "dir", "folder", "directory",
        "page", "template", "tpl", "include", "require",
        "view", "render", "layout", "theme", "skin",
        "doc", "document", "attachment", "download", "dl",
        "load", "open", "read", "show", "display",
        "pdf", "image", "img", "photo", "pic",
        "css", "style", "stylesheet", "js", "script",
        "font", "fontface", "icon", "logo", "banner",
        "lang", "language", "locale", "translation", "i18n",
        "config", "settings", "ini", "conf", "properties",
        "log", "logs", "error", "debug", "trace",
        "cache", "tmp", "temp", "data", "storage",
        "module", "plugin", "extension", "addon", "component",
        "lib", "library", "vendor", "package", "dependency",
        "resource", "asset", "media", "static", "public",
        "private", "protected", "internal", "core", "base",
        "upload", "uploads", "files", "images", "documents",
        "sitemap", "robots", "crossdomain", "manifest", "package",
        "backup", "old", "archive", "history", "previous",
        "php", "asp", "aspx", "jsp", "cfm", "cgi",
        "xml", "json", "yaml", "yml", "toml", "ini",
        "html", "htm", "shtml", "phtml", "php5", "php7",
        "txt", "text", "csv", "log", "sql", "db",
        "bak", "old", "orig", "copy", "save", "tmp",
        "swp", "swo", "~", ".swp", ".bak", ".orig",
        "composer", "package", "yarn", "npm", "bower",
        "docker", "dockerfile", "docker-compose", "k8s", "kubernetes",
        "env", "environment", "secrets", "credentials", "keys",
        "pem", "crt", "key", "cert", "certificate",
        "token", "secret", "password", "passwd", "shadow",
        "htpasswd", "htaccess", "wp-config", "settings", "database",
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys",
        "known_hosts", "ssh_config", "sshd_config", "mysql", "my.cnf",
        "wp-config.php", "config.php", "configuration.php", "web.config",
        "appsettings.json", "settings.py", "settings.yml", "config.yml",
        "application.properties", "application.yml", "application.yaml",
        "credentials.json", "service-account.json", "keyfile.json",
        "terraform.tfvars", "terraform.tfstate", "secrets.yml",
        "vault", "consul", "etcd", "zookeeper", "kafka",
    ],
    "ssti": [
        "template", "tpl", "view", "render", "page",
        "name", "username", "title", "subject", "message",
        "body", "content", "text", "description", "summary",
        "email", "mail", "to", "from", "sender",
        "preview", "preview_html", "html", "markdown", "rich",
        "format", "output", "type", "mode", "layout",
        "theme", "skin", "style", "design", "template_name",
        "component", "partial", "section", "block", "fragment",
        "include", "extends", "import", "macro", "embed",
        "lang", "language", "locale", "translation", "i18n",
        "custom", "customField", "custom_field", "meta", "metadata",
        "greeting", "welcome", "signature", "footer", "header",
        "notification", "alert", "flash", "notice", "banner",
        "report", "export", "pdf", "csv", "xml",
        "invoice", "receipt", "order", "booking", "confirmation",
        "reset", "verify", "confirm", "activate", "welcome",
        "newsletter", "digest", "summary", "weekly", "daily",
        "error", "404", "500", "maintenance", "offline",
        "sitemap", "feed", "rss", "atom", "json",
        "search", "query", "q", "s", "keyword",
        "sort", "filter", "group", "order", "dir",
        "__class__", "__bases__", "__mro__", "__subclasses__",
        "__globals__", "__init__", "__dict__", "__builtins__",
        "config", "settings", "self", "request", "app",
        "session", "user", "current_user", "g", "flask",
        "url_for", "get_flashed_messages", "lipsum", "cycler",
        "joiner", "namespace", "range", "dict", "lipsum",
        "getattr", "setattr", "mro", "subclasses", "builtins",
        "import", "os", "sys", "subprocess", "popen",
        "open", "file", "read", "write", "eval",
        "exec", "compile", "__import__", "reload", "globals",
    ],
}


def params_for(category: str) -> List[str]:
    """Return the parameter name list for a vulnerability category."""
    return _PARAMS.get(category, [])


def all_params() -> Set[str]:
    """Union of all known parameter names across all categories."""
    return {p for v in _PARAMS.values() for p in v}


def params_for_categories(categories: List[str]) -> List[str]:
    """Deduplicated union of params from multiple categories."""
    seen = set()
    out = []
    for cat in categories:
        for p in _PARAMS.get(cat, []):
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


def short_params(threshold: int = 3) -> List[str]:
    """Single/double-letter params that scanners most commonly miss."""
    return sorted(p for p in all_params() if len(p) <= threshold)


def top_params(category: str, n: int = 20) -> List[str]:
    """Top N params for a category (first in the list are most common)."""
    return _PARAMS.get(category, [])[:n]


def param_stats() -> Dict[str, int]:
    """Count of params per category."""
    return {k: len(v) for k, v in _PARAMS.items()}


def find_params(category: str, keyword: str) -> List[str]:
    """Find params containing a keyword in a given category."""
    kw = keyword.lower()
    return [p for p in _PARAMS.get(category, []) if kw in p.lower()]


def param_fingerprint(value: str) -> Optional[str]:
    """Try to guess the vulnerability class from a parameter name."""
    value = value.lower().strip()
    for cat, params in _PARAMS.items():
        if value in params:
            return cat
    return None


__all__ = [
    'params_for', 'all_params', 'params_for_categories',
    'short_params', 'top_params', 'param_stats', 'find_params',
    'param_fingerprint',
]