from __future__ import annotations

"""Constantes e valores padrao usados por todo o RavenEye."""


# ==================================================================
# CONSTANTES — versão e arquivos
# ==================================================================
TOOL_VERSION = "6.6.6"


TOOL_NAME = "RavenEye"


CONFIG_FILE = "raven_eye_config.json"


# ==================================================================
# CONSTANTES — User-Agents para rotação
# ==================================================================
USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


# ==================================================================
# CONSTANTES — Subdomain Takeover fingerprints
# ==================================================================
TAKEOVER_FINGERPRINTS: dict[str, str] = {
    "GitHub Pages":   "There isn't a GitHub Pages site here",
    "Heroku":         "No such app",
    "Fastly":         "Fastly error: unknown domain",
    "Shopify":        "Sorry, this shop is currently unavailable",
    "Tumblr":         "There's nothing here",
    "WordPress.com":  "Do you want to register",
    "Ghost":          "The thing you were looking for is no longer here",
    "Surge.sh":       "project not found",
    "AWS S3":         "NoSuchBucket",
    "Azure":          "404 Web Site not found",
    "Pantheon":       "The gods are wise",
    "Zendesk":        "Help Center Closed",
    "Unbounce":       "The requested URL was not found",
    "HubSpot":        "Domain not found",
    "Bitbucket":      "Repository not found",
    "Intercom":       "This page is reserved for artistic inspiration",
    "Freshdesk":      "There is no helpdesk here",
    "Fly.io":         "404 Not Found",
    "Netlify":        "Not Found - Request ID",
    "ReadTheDocs":    "unknown to Read the Docs",
    "Tilda":          "Please renew your subscription",
}


# ==================================================================
# CONSTANTES — Patterns de secrets em JavaScript
# ==================================================================
SECRET_PATTERNS: dict[str, str] = {
    "AWS Access Key":      r"AKIA[0-9A-Z]{16}",
    "Google API Key":      r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token":        r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}",
    "JWT Token":           r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "Slack Token":         r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
    "Firebase URL":        r"https://[a-z0-9\-]+\.firebaseio\.com",
    "Stripe Live Key":     r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Publishable":  r"pk_live_[0-9a-zA-Z]{24}",
    "SendGrid Key":        r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
    "Mailgun Key":         r"key-[0-9a-zA-Z]{32}",
    "API Key generica":    r"(?i)(api[_\-]?key|apikey|api[_\-]?secret)['\"\s:=]+['\"]([A-Za-z0-9_\-]{20,50})['\"]",
    "Password hardcoded":  r"(?i)(password|passwd|pwd)['\"\s:=]+['\"]([^'\"]{8,50})['\"]",
    "Internal URL":        r"https?://(staging|dev|internal|test|qa|uat|preprod)\.[a-z0-9\.\-]+",
    "Bearer Token":        r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}",
    "RSA Private Key":     r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "DB Connection":       r"(?i)(mongodb|mysql|postgresql|redis|mssql):\/\/[^\s\"'<>]+",
    "Mapbox Token":        r"pk\.eyJ1[A-Za-z0-9\._\-]+",
    "NPM Token":           r"npm_[A-Za-z0-9]{36}",
    "OpenAI Key":          r"sk-[A-Za-z0-9]{48}",
    "Anthropic Key":       r"sk-ant-[A-Za-z0-9\-_]{95}",
    "GCP Service Account": r"\"type\"\s*:\s*\"service_account\"",
}


# ==================================================================
# CONSTANTES — Security headers
# ==================================================================
SECURITY_HEADERS: dict[str, dict[str, str]] = {
    "Strict-Transport-Security":    {"severity": "MEDIO",  "desc": "HSTS ausente — downgrade HTTP possivel"},
    "Content-Security-Policy":      {"severity": "MEDIO",  "desc": "CSP ausente — XSS mais exploravel"},
    "X-Frame-Options":              {"severity": "BAIXO",  "desc": "Clickjacking nao prevenido"},
    "X-Content-Type-Options":       {"severity": "BAIXO",  "desc": "MIME sniffing nao prevenido"},
    "Referrer-Policy":              {"severity": "INFO",   "desc": "Referrer Policy nao definida"},
    "Permissions-Policy":           {"severity": "INFO",   "desc": "Permissions Policy nao definida"},
    "Cross-Origin-Opener-Policy":   {"severity": "INFO",   "desc": "COOP nao definida"},
    "Cross-Origin-Resource-Policy": {"severity": "INFO",   "desc": "CORP nao definida"},
    "Cache-Control":                {"severity": "INFO",   "desc": "Cache-Control nao definido"},
}


# ==================================================================
# CONSTANTES — Versões desatualizadas em headers
# ==================================================================
OUTDATED_VERSIONS: dict[str, dict[str, str]] = {
    r"Apache/([12]\.\d+\.\d+)": {"name": "Apache", "safe_from": "2.4.50"},
    r"nginx/(\d+\.\d+\.\d+)":   {"name": "nginx",  "safe_from": "1.24.0"},
    r"PHP/(\d+\.\d+\.\d+)":     {"name": "PHP",    "safe_from": "8.1.0"},
    r"OpenSSL/(\d+\.\d+\.\d+)": {"name": "OpenSSL","safe_from": "3.0.0"},
    r"IIS/(\d+\.\d+)":          {"name": "IIS",    "safe_from": "10.0"},
    r"Tomcat/(\d+\.\d+\.\d+)":  {"name": "Tomcat", "safe_from": "9.0.70"},
}


# ==================================================================
# CONSTANTES — Parâmetros de Open Redirect
# ==================================================================
REDIRECT_PARAMS: list[str] = [
    "url", "redirect", "redirect_url", "redirectUrl", "next", "return",
    "returnUrl", "return_url", "goto", "dest", "destination", "forward",
    "location", "target", "redir", "redirect_uri", "callback", "continue",
    "out", "view", "go", "link", "to", "logoutUrl",
]


# ==================================================================
# CONSTANTES — Padrões de error disclosure
# ==================================================================
ERROR_PATTERNS: dict[str, str] = {
    "Python Traceback":  r"Traceback \(most recent call last\)",
    "Java Stack Trace":  r"at [\w\$]+\.[\w\$]+\([\w\.]+:\d+\)",
    "ASP.NET Exception": r"System\.Web\.Http|System\.Web\.Mvc|\.NET Framework",
    "PHP Fatal Error":   r"Fatal error:.+in .+\.php on line \d+",
    "PHP Warning":       r"<b>Warning</b>:.+on line <b>\d+</b>",
    "Rails Error":       r"ActiveRecord::\w+Error|ActionController::\w+Error",
    "Django Error":      r"django\.core\.exceptions|Django Version:",
    "Oracle Error":      r"ORA-\d{5}:",
    "MySQL Error":       r"You have an error in your SQL syntax|MySQL server version",
    "MSSQL Error":       r"Microsoft OLE DB Provider for SQL Server",
    "PostgreSQL Error":  r"pg_query\(\)|ERROR:  syntax error at or near",
    "MongoDB Error":     r"MongoError:|MongoServerError:",
    "PDO SQL Error":     r"SQLSTATE\[",
    "Node.js Error":     r"Error: Cannot find module|UnhandledPromiseRejection",
    "Spring Boot Error": r"org\.springframework\.|java\.lang\.\w+Exception",
}


# ==================================================================
# CONSTANTES — Wordlist de nomes de parametros HTTP (descoberta de parametros)
# Usada pelo teste de payload/parametros do crawler. Diferente da wordlist
# de senhas (EXTRA_PASSWORDS) — aqui sao nomes de PARAMETRO reais, no estilo
# do que ferramentas como Arjun/ParamSpider usam.
# ==================================================================
COMMON_PARAM_NAMES: list[str] = [
    # Identificacao / navegacao
    "id", "uid", "user_id", "userid", "user", "username", "account", "acct",
    "page", "p", "pg", "offset", "limit", "size", "count", "num", "index",
    "next", "prev", "cursor", "token", "session", "sid", "sessionid",
    # Busca / filtro
    "q", "query", "search", "s", "keyword", "keywords", "term", "filter",
    "category", "cat", "type", "sort", "order", "orderby", "dir", "view",
    # Redirect / navegacao (ja cobertos em REDIRECT_PARAMS mas uteis aqui tambem)
    "url", "redirect", "redirect_url", "return", "return_url", "next_url",
    "goto", "dest", "destination", "continue", "callback", "ref", "referer",
    "source", "src", "target",
    # Arquivos / caminhos
    "file", "filename", "path", "dir", "folder", "load", "include",
    "template", "page_id", "doc", "document", "download", "upload",
    # Acao / controle
    "action", "cmd", "command", "exec", "func", "function", "method",
    "module", "controller", "route", "endpoint", "op", "do",
    # Debug / config
    "debug", "test", "mode", "env", "config", "admin", "preview_mode",
    "format", "output", "lang", "locale", "language", "timezone",
    # Autenticacao / API
    "api_key", "apikey", "key", "auth", "access_token", "jwt", "secret",
    "client_id", "client_secret", "code", "state", "nonce",
    # Dados / conteudo
    "data", "json", "xml", "content", "body", "payload", "value", "input",
    "name", "title", "email", "phone", "message", "comment", "text",
    # E-commerce
    "product", "product_id", "item", "item_id", "order", "order_id", "cart",
    "price", "qty", "quantity", "coupon", "promo", "sku",
    # Diversos frequentes em bug bounty
    "utm_source", "utm_campaign", "ref_id", "tracking_id", "affiliate",
    "version", "v", "api_version", "csrf", "csrf_token", "xss", "sql",
]


# ==================================================================
# CONSTANTES — Ranges de IP publicos do Cloudflare
# Publicados oficialmente pela propria Cloudflare em cloudflare.com/ips
# (transparencia proposital, para quem precisa allowlist-ar o proxy deles).
# Usado para identificar quando um IP NAO esta atras do Cloudflare — util
# pra achar o IP de origem real quando um subdominio esquecido (mail, dev,
# staging antigo etc.) nao passa pelo proxy. Pode ficar desatualizado com
# o tempo; RavenEye tenta atualizar via API oficial quando ha rede
# disponivel, com esta lista como fallback (ver scanners.get_cloudflare_ranges).
# ==================================================================
CLOUDFLARE_IPV4_RANGES: list[str] = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
CLOUDFLARE_IPV6_RANGES: list[str] = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]


# ==================================================================
# CONSTANTES — Wordlist embutida de subdominios comuns
# Usada pela enumeracao ativa de subdominios via DNS (brute_subdomains)
# ==================================================================
SUBDOMAIN_WORDLIST: list[str] = [
    # Basicos / web
    "www", "www2", "www3", "web", "site", "home", "beta", "alpha", "demo",
    "sandbox", "preview", "canary", "next", "new", "old", "legacy",
    # Mail
    "mail", "mail1", "mail2", "smtp", "smtp1", "smtp2", "pop", "pop3",
    "imap", "webmail", "mx", "mx1", "mx2", "relay", "autodiscover",
    "owa", "exchange", "mailgw", "mailer", "newsletter",
    # Admin / painel
    "admin", "administrator", "cpanel", "whm", "webadmin", "panel",
    "portal", "dashboard", "manage", "management", "backend", "backoffice",
    "console", "controlpanel", "sysadmin", "root",
    # Dev / ambientes
    "dev", "dev1", "dev2", "develop", "development", "staging", "stage",
    "test", "test1", "test2", "testing", "qa", "uat", "preprod", "prod",
    "production", "sandbox2", "lab", "labs", "internal", "intranet",
    "extranet", "local", "localhost",
    # Infra
    "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2", "server", "srv",
    "srv1", "srv2", "host", "vpn", "vpn1", "vpn2", "proxy", "gateway",
    "gw", "lb", "loadbalancer", "cluster", "node1", "node2", "web1",
    "web2", "web3", "app1", "app2", "backup", "backups", "ftp", "ftp1",
    "ftp2", "sftp", "ssh", "telnet",
    # API / apps
    "api", "api1", "api2", "apiv1", "apiv2", "rest", "graphql", "ws",
    "websocket", "app", "apps", "mobile", "m", "api-docs", "docs",
    "swagger", "developer", "developers",
    # CDN / assets
    "cdn", "cdn1", "cdn2", "static", "assets", "img", "images", "media",
    "video", "videos", "files", "file", "download", "downloads",
    "upload", "uploads", "cache", "edge",
    # Databases / devops
    "db", "database", "mysql", "postgres", "postgresql", "mongo",
    "mongodb", "redis", "elastic", "elasticsearch", "kibana", "grafana",
    "prometheus", "jenkins", "ci", "cd", "git", "gitlab", "github",
    "bitbucket", "jira", "confluence", "sonarqube", "registry", "docker",
    "k8s", "kubernetes",
    # Comunicacao / colaboracao
    "chat", "meet", "video-call", "zoom", "teams", "sharepoint", "wiki",
    "kb", "knowledgebase", "faq", "helpdesk", "support", "help", "status",
    # Auth / identidade
    "sso", "auth", "login", "id", "identity", "accounts", "account",
    "my", "oauth", "idp",
    # Monitoramento
    "monitor", "monitoring", "metrics", "logs", "log", "logging",
    "analytics", "tracking", "stats", "statistics", "health",
    # Negocio
    "shop", "store", "cart", "checkout", "payment", "payments",
    "billing", "invoice", "invoices", "orders", "crm", "erp", "hr",
    "finance", "payroll", "reports", "report",
    # Marketing / institucional
    "blog", "forum", "community", "news", "press", "events", "careers",
    "jobs", "partners", "investors", "legal", "privacy", "terms",
    "security", "trust", "compliance", "audit", "contact", "about",
    # Mobile / plataformas
    "ios", "android", "apk", "app-store", "play",
]


# ==================================================================
# CONSTANTES — Wordlist embutida de senhas (BR + internacional)
# Usada como fallback e complemento ao bruteforce
# ==================================================================
EXTRA_PASSWORDS: list[str] = [
    # Nomes brasileiros com anos
    "Carlos1970","Carlos1968","Jose1960","Jose1972","Joao1965","Joao1970",
    "Paulo1962","Paulo1975","Marcos1969","Antonio1950","Antonio1964",
    "Roberto1966","Fernando1968","Ricardo1970","Eduardo1965","Sergio1960",
    "Alberto1959","Luiz1962","Marcelo1975","Fabio1978","Andre1977",
    "Bruno1985","Gustavo1988","Renato1973","Ronaldo1976","Pedro1967",
    "Daniel1980","Lucas1990","Mateus1992","Gabriel1999","Gabriel2000",
    "Mariana1985","Juliana1987","Fernanda1988","Patricia1979","Carla1980",
    "Ana1985","Maria1960","Maria1970","Maria1980","Maria1990","Sandra1968",
    "Luciana1982","Cristina1974","Claudia1973","Beatriz1995","Vanessa1987",
    "Camila1993","Bianca1996","Monica1979","Debora1987","Adriana1983",
    "Paula1985","Simone1976","Helena1963","Rita1962","Denise1980",
    "DonaMaria1950","SeuJose1948","FamiliaSilva2020","FamiliaSouza2015",
    "Joaozinho1975","Carlinhos1980","Paulinho1990","Zezinho1970",
    # Senhas comuns
    "123456","123456789","12345678","12345","1234567","password","senha",
    "qwerty","abc123","111111","123123","admin","welcome","letmein","000000",
    "iloveyou","monkey","dragon","master","shadow","sunshine","passw0rd",
    "trustno1","superman","pokemon","naruto","batman","zaq12wsx","qazwsx",
    "1q2w3e4r","654321","987654321","11111111","121212","112233","123321",
    "159753","147258","258369","senha123","senha1234","admin123","root",
    "toor","guest","user","login","teste","teste123","abc123456","abcd1234",
    "qwerty123","qwertyuiop","asdfghjkl","zxcvbnm","pass123","pass1234",
    "senha2024","senha2025","senha2026","brasil","brasil123","rio123",
    "saopaulo","flamengo","corinthians","palmeiras","vasco","cruzeiro",
    "gremio","neymar","ronaldo","messi","cr7","luffy","goku","vegeta",
    "pikachu","naruto123","sasuke","dragonball","freefire","ff123456",
    "pubg123","minecraft","mc123456","roblox","fortnite","tiktok",
    "facebook","fb123456","google","gmail123","youtube","netflix","amazon",
    "windows","linux","ubuntu","kali123","hacker","hack123","security",
    "adminadmin","password1","password123","password1234","welcome123",
    "letmein123","super123","superuser","administrator","root123","toor123",
    "guest123","user123","login123","default","default123","changeme",
    "temp123","test1234","demo123","secret","secret123","hidden123",
    "private123","network123","server123","backup123","config123",
    "segredo123","seguranca","protecao","firewall","antivirus","exploit",
    "payload","backdoor","rootkit","bruteforce","hacker","pix123",
    "banco123","credito123","bitcoin123","ethereum","wallet123","token123",
    "python123","java123","html123","sql123","database123","api123",
    # Variações com símbolos
    "password!","password@","password#","senha!","senha@","admin!","admin@",
    "root!","root@","123456!","123456@","qwerty!","qwerty@","abc123!",
    "1234","1234567890","0987654321","12121212","adminadmin","userpass",
    # Complexas com maiúsculas
    "SenhaForte!1","UltraSafe#2026","MegaSecure@99","HardPass$777",
    "TopSecret%321","FireWall!Secure","AntiVirus#On","Crypto$Hash123",
    "KeyMaster!2026","SafeZone#8844","LockDown@777","GateKeeper$123",
    "CyberShield&321","NeoMatrix*456","IronWall%999","ThunderBolt010",
    "ShadowWolf$606","NightHawk%707","FireStorm&808","IceBreaker909",
    "DataStream!456","ByteForce@678","CodePulse$789","SecureNode#654",
    "CoreAccess!549","SuperNode@769","UltraAccess$879","MegaSystem989",
    "VaultSystem987","LockSystem098","MainFrame439","AlphaKey505",
    "BetaLock606","GammaPass707","DeltaSafe808","OmegaSafe050",
    "PrimeLock060","CyberVault505","SafeAccess707","TrustCore808",
    # Técnicas / DevOps
    "Python_code789","Java_class000","GoLang_func456","Rust_safe789",
    "React_ui456","Node_server123","Api_rest456","Http_200_OK",
    "Ssh_connect789","Ip192168001","Router#1234","Wifi@Home567",
    "Server_Main000","Client_User123","Guest_Login456","Default_Config789",
    "Backup_Data123","Install_App123","Debug_Mode000","Test_Case123",
    "Final_Deploy123","Version1.0.0","Version2.0.1","Build_123456",
    "Release_2026","Fix_bug123","Feature_New456","Config_Set789",
    # BR maiúsculas
    "PASSWORD","SENHA","ADMINISTRADOR","USUARIO","LOGIN123","ACESSO123",
    "SISTEMA","SERVIDOR","BANCO123","SEGURANCA123","BRASIL2024","BRASIL2025",
    "ANO2024","ANO2025","ANO2026","ADMIN1234","ROOT1234","MASTER1234",
    "SUPERUSER123","DEFAULT1234","TESTE12345","ACESSO_TOTAL","ACESSO_ROOT",
    "SENHAFORTE","SENHASEGURA","ACESSO_SEGURO","SISTEMA_SEGURO",
]


# ==================================================================
# CONFIGURAÇÃO PADRÃO
# ==================================================================
DEFAULT_CONFIG: dict = {
    "max_pages": 100,
    "delay": 0.3,
    "max_depth": 5,
    "bf_attempts": 500,
    "report_link_limit": 200,
    "user_agent": USER_AGENTS[0],
    "max_depth_nuke": 5,
    "enum_paths_limit": 200,
    "enum_endpoints_limit": 200,
    "enum_parameters_limit": 60,
    "shodan_api_key": "",
    "virustotal_api_key": "",
    "google_cse_api_key": "",
    "google_cse_id": "",
    "custom_dorks_file": "",
    "wordlist_hashes": {},
    "dns_rate_limit": 30,
    "param_probe_limit": 80,
    "max_runtime_seconds": 900,
    "log_file": "raveneye.log",
    "log_level": "WARNING",
    "verbose": 0,
    "proxy": "",
    "max_workers": 5,
    "use_js_render": False,
    "scope_file": "",
    "wayback_from_year": 2020,
    "google_hacking_mode": "scan",
    "stealth_mode": False,
    "database_path": "data/raveneye.db",
    "scan_cache_ttl": 3600,
    "scanner_rate_limit": 8.0,
    "scanner_max_workers": 6,
    "multi_target_enabled": False,
    "max_targets": 50,
}


# ==================================================================
# FUNÇÕES — protecao SSRF
# ==================================================================
_SSRF_BLOCKED_HOSTS: set[str] = {
    "169.254.169.254", "metadata.google.internal", "169.254.170.2",
    "instance-data", "metadata", "localhost",
}


# ==================================================================
# FUNÇÕES — Google Dorks automatizado (Google Custom Search API)
# ==================================================================
_DORK_INTERESTING_KEYWORDS: dict[str, list[str]] = {
    "Arquivo sensivel": [".env", ".sql", ".bak", ".old", ".log", ".config", ".yml",
                          ".yaml", ".pem", ".key", ".sqlite", "backup", "dump"],
    "Admin/Login": ["admin", "login", "signin", "cpanel", "phpmyadmin", "wp-admin",
                     "dashboard", "painel"],
    "API/Docs exposta": ["swagger", "graphql", "api-docs", "openapi", "api/v1", "api/v2"],
    "Diretorio listado": ["index of", "parent directory", "directory listing"],
    "Config/Debug exposto": ["phpinfo", "debug", "stack trace", "server-status",
                              "wp-config", "web.config"],
    "Codigo/versionamento exposto": [".git", "composer.json", "package.json"],
    "Credenciais/Secrets": ["password", "senha", "api_key", "secret", "token",
                             "access_key"],
}


# ==================================================================
# FUNÇÕES — JWT Weaknesses
# ==================================================================
_JWT_COMMON_SECRETS: list[str] = [
    "secret", "Secret123", "your-256-bit-secret", "jwt_secret", "jwtsecret",
    "changeme", "supersecret", "mysecretkey", "secretkey", "123456",
    "password", "admin", "key", "jwt", "token", "auth_secret",
    "your-secret-key", "test", "development", "production", "qwerty",
]
