import ipaddress
import socket
import ssl
import time
from html.parser import HTMLParser
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse, urldefrag
import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Force l'utilisation de HTTPS",
    "Content-Security-Policy": "Définit les sources de contenu autorisées",
    "X-Content-Type-Options": "Réduit les risques de MIME sniffing",
    "Referrer-Policy": "Contrôle les informations de provenance transmises",
    "Permissions-Policy": "Limite certaines fonctionnalités du navigateur",
    "X-Frame-Options": "Contribue à prévenir le clickjacking",
}
REDIRECT_CODES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 5
TIMEOUT = 8
MAX_BODY_BYTES = 300_000
USER_AGENT = "CyberAuditDesktop/1.1 (non-destructive audit)"
EXPOSED_PATHS = {
    "/.env": ("Fichier de configuration .env", "critique"),
    "/.git/HEAD": ("Métadonnées du dépôt Git", "élevé"),
    "/.DS_Store": ("Métadonnées macOS", "faible"),
    "/phpinfo.php": ("Page PHPInfo", "moyen"),
    "/server-status": ("Page de statut serveur", "moyen"),
    "/swagger.json": ("Spécification Swagger", "faible"),
    "/openapi.json": ("Spécification OpenAPI", "faible"),
    "/actuator/env": ("Endpoint Spring Actuator env", "élevé"),
    "/debug": ("Endpoint de débogage potentiel", "moyen"),
    "/backup.zip": ("Archive de sauvegarde potentielle", "élevé"),
}
TECH_SIGNATURES = {
    "WordPress": ["wp-content/", "wp-includes/"],
    "Drupal": ["drupal.settings", "sites/default/files"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Django": ["csrftoken", "django"],
    "ASP.NET": ["__viewstate", "asp.net"],
    "React": ["reactroot", "__react"],
    "Next.js": ["/_next/", "__next_data__"],
}
# Chemins courants anglais et français à vérifier sans session.
# À adapter au site audité : les URL varient selon le CMS et l'application.
# Un code HTTP 200 ne prouve pas à lui seul qu'une ressource privée est exposée.
DEFAULT_PRIVATE_PATHS = [
    # Chemins fréquemment utilisés en anglais
    "/account",
    "/my-account",
    "/profile",
    "/dashboard",
    "/admin",
    "/settings",
    "/billing",
    "/orders",
    "/api/me",
    "/api/profile",
    # Variantes courantes en français
    "/compte",
    "/mon-compte",
    "/profil",
    "/tableau-de-bord",
    "/administration",
    "/parametres",
    "/paramètres",
    "/facturation",
    "/commandes",
    "/mes-commandes",
    "/paiement",
    "/coordonnees",
    "/coordonnées",
    "/informations-personnelles",
    "/espace-client",
    "/espace-membre",
    "/api/mon-compte",
    "/api/profil",
]

SQL_ERROR_MARKERS = [
    "sql syntax", "mysql_fetch", "mysqli_", "pdoexception", "sqlite_error",
    "sqlite3.operationalerror", "postgresql error", "pg_query(", "ora-01756",
    "unclosed quotation mark", "odbc sql server driver", "sqlstate[",
]


import re
from difflib import SequenceMatcher


def _normalize_sqli_body(body):
    """Normalise certains éléments variables sans effacer tout le contenu utile."""
    text = (body or "").lower()

    # Supprime les espaces pour limiter les différences de mise en forme.
    text = re.sub(r"\s+", " ", text)

    # Masque les valeurs courantes de jetons dynamiques.
    text = re.sub(
        r'(?i)(csrf|nonce|request[-_]?id|trace[-_]?id)'
        r'(["\'\s:=]+)[a-z0-9._-]+',
        r'\1\2<variable>',
        text
    )
    return text.strip()


def _sqli_similarity(body_a, body_b):
    """Renvoie une similarité de contenu entre 0 et 1."""
    a = _normalize_sqli_body(body_a)
    b = _normalize_sqli_body(body_b)

    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0

    return SequenceMatcher(None, a, b, autojunk=False).ratio()


def _sqli_fetch(session, url):
    """Effectue une requête GET limitée et retourne un résultat exploitable."""
    response, error, body = _request(
        session, url, read_body=True, limit=100_000
    )

    if response is None:
        return None, error, ""

    try:
        result = (response.status_code, body)
    finally:
        response.close()

    return result, "", ""


def _sqli_probe_url(parsed, params, index, name, value):
    """Construit une URL en modifiant uniquement le paramètre ciblé."""
    pairs = list(params)
    pairs[index] = (name, value)
    return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))

def validate_url(url):
    """Accepte HTTP/80 et HTTPS/443 uniquement vers une adresse IP publique."""
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return False, "URL invalide."
    scheme = parsed.scheme.lower()
    expected_port = 80 if scheme == "http" else 443 if scheme == "https" else None
    if (expected_port is None or not parsed.hostname or parsed.username or parsed.password
            or port not in (None, expected_port)):
        return False, "Seules les URL HTTP (port 80) et HTTPS (port 443) sont acceptées."
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return False, "Les noms d'hôte locaux sont interdits."
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(
            hostname, expected_port, type=socket.SOCK_STREAM
        )}
        if not addresses:
            return False, "Aucune adresse IP trouvée."
        for address in addresses:
            if not ipaddress.ip_address(address).is_global:
                return False, f"Destination refusée : adresse IP non publique ({address})."
    except (OSError, ValueError):
        return False, "Impossible de vérifier l'adresse IP de destination."
    return True, ""


def _read_limited(response, limit=MAX_BODY_BYTES):
    chunks, total = [], 0
    try:
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            chunk = chunk[:max(0, limit - total)]
            chunks.append(chunk)
            total += len(chunk)
            if total >= limit:
                break
    except requests.RequestException:
        pass
    return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")


def _request(session, url, read_body=False, limit=MAX_BODY_BYTES):
    valid, reason = validate_url(url)
    if not valid:
        return None, "Destination refusée : " + reason, ""
    try:
        response = session.get(url, timeout=TIMEOUT, allow_redirects=False, verify=True,
                               stream=True, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        body = _read_limited(response, limit) if read_body else ""
        return response, "", body
    except requests.exceptions.SSLError:
        return None, "Certificat TLS invalide ou non vérifiable.", ""
    except requests.RequestException as exc:
        return None, f"Erreur de requête : {exc}", ""


def get_tls_certificate_report(hostname: str) -> list[str]:
    report = ["", "5. CERTIFICAT TLS DÉTAILLÉ"]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as tls:
                cert, tls_version = tls.getpeercert(), tls.version()
        report.append(f"Version TLS négociée : {tls_version or 'inconnue'}")
        if not cert:
            return report + ["Informations du certificat indisponibles."]
        def fmt(entries):
            parts = [f"{key}={value}" for group in entries for key, value in group]
            return ", ".join(parts) or "Non communiqué"
        report.append("Sujet : " + fmt(cert.get("subject", ())))
        report.append("Émetteur : " + fmt(cert.get("issuer", ())))
        sans = [v for kind, v in cert.get("subjectAltName", ()) if kind == "DNS"]
        report.append("Noms DNS : " + (", ".join(sans[:30]) if sans else "non communiqués"))
        if cert.get("notBefore"):
            start = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), tz=timezone.utc)
            report.append(f"Valide à partir du : {start:%d/%m/%Y %H:%M UTC}")
        if cert.get("notAfter"):
            expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
            days = (expiry - datetime.now(timezone.utc)).days
            report.append(f"Expiration : {expiry:%d/%m/%Y %H:%M UTC} ({days} jour(s) restant(s))")
            report.append("[ALERTE] Certificat expiré." if days < 0 else
                          "[AVERTISSEMENT] Expiration dans 30 jours ou moins." if days <= 30 else
                          "[OK] Validité restante supérieure à 30 jours.")
    except (OSError, ssl.SSLError, ValueError) as exc:
        report.append(f"Impossible de lire le certificat TLS : {exc}")
    return report


def check_tls_protocols(hostname: str) -> list[str]:
    report = ["", "6. PROTOCOLES TLS"]
    versions = [("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None), True),
                ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None), True),
                ("TLS 1.2", getattr(ssl.TLSVersion, "TLSv1_2", None), False),
                ("TLS 1.3", getattr(ssl.TLSVersion, "TLSv1_3", None), False)]
    for label, version, weak in versions:
        if version is None:
            report.append(f"[NON DISPONIBLE] {label} : non pris en charge par Python/OpenSSL.")
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_default_certs()
            ctx.minimum_version = ctx.maximum_version = version
            with socket.create_connection((hostname, 443), timeout=4) as raw:
                with ctx.wrap_socket(raw, server_hostname=hostname):
                    pass
            report.append(f"[RISQUE] {label} accepté par le serveur." if weak else f"[OK] {label} accepté par le serveur.")
        except (OSError, ssl.SSLError, ValueError):
            report.append(f"[NON NÉGOCIÉ] {label} : refusé ou impossible à confirmer.")
    report.append("Un échec de négociation ne prouve pas toujours que le protocole est désactivé.")
    return report


def _check_cookies(response):
    report = ["", "3. COOKIES"]
    try:
        cookies = response.raw.headers.getlist("Set-Cookie")
    except (AttributeError, TypeError):
        cookies = []
    if not cookies and response.headers.get("Set-Cookie"):
        cookies = [response.headers["Set-Cookie"]]
    if not cookies:
        return report + ["Aucun cookie Set-Cookie reçu sur la réponse finale."]
    for i, cookie in enumerate(cookies, 1):
        attrs = {p.strip().split("=", 1)[0].lower() for p in cookie.split(";") if p.strip()}
        name = cookie.split("=", 1)[0].strip() or f"cookie {i}"
        missing = [a for a in ("secure", "httponly", "samesite") if a not in attrs]
        report.append(f"Cookie {i} ({name}) : " + ("Secure/HttpOnly/SameSite présents" if not missing else "attribut(s) absent(s) : " + ", ".join(missing)))
    report.append("L'importance des attributs dépend du rôle de chaque cookie.")
    return report


def _check_technology(body, response):
    report = ["", "7. TECHNOLOGIES ET INDICES"]
    hay = (body + "\n" + "\n".join(f"{k}: {v}" for k, v in response.headers.items())).lower()
    found = [tech for tech, markers in TECH_SIGNATURES.items() if any(m.lower() in hay for m in markers)]
    report.append("Technologies indicatives : " + (", ".join(found) if found else "aucune signature évidente"))
    report.append(f"Server : {response.headers.get('Server', 'non communiqué')}")
    report.append(f"X-Powered-By : {response.headers.get('X-Powered-By', 'non communiqué')}")
    report.append("Les signatures et bannières peuvent être masquées ou erronées ; aucune version vulnérable n'est confirmée ici.")
    return report


def _check_passive_sqli_xss(body):
    report = ["", "8. INDICES PASSIFS SQLi / XSS"]
    low = body.lower()
    hits = [m for m in SQL_ERROR_MARKERS if m in low]
    report.append("[SUSPICION] Erreur SQL potentiellement exposée : " + ", ".join(hits[:5]) if hits else "[NON DÉTECTÉ] Aucune erreur SQL courante visible dans la page analysée.")
    report.append("[INFORMATION] Des balises/attributs JavaScript apparaissent dans le HTML." if any(x in low for x in ("<script", "onerror=", "javascript:")) else "[NON CONCLUANT] Aucun marqueur HTML/JavaScript évident.")
    report.append("Contrôle passif uniquement : aucun payload SQLi/XSS n'est envoyé. Une absence d'indice ne prouve pas l'absence de faille.")
    return report


def _check_exposed_paths(session, base_url):
    report = ["", "9. RESSOURCES POTENTIELLEMENT EXPOSÉES", "Requêtes GET limitées ; maximum 1 Ko lu par ressource."]
    count = 0
    for path, (description, severity) in EXPOSED_PATHS.items():
        target = urljoin(base_url, path)
        resp, error, body = _request(session, target, read_body=True, limit=1024)
        if resp is None:
            report.append(f"[NON VÉRIFIÉ] {path} — {error}")
            continue
        try:
            status = resp.status_code
            low = body.lower()
            relevant = status in (200, 206)
            if path == "/.env": relevant = relevant and any(x in body for x in ("=", "DB_", "API_KEY", "SECRET")) and "not found" not in low
            elif path == "/.git/HEAD": relevant = relevant and low.startswith("ref:")
            elif path == "/phpinfo.php": relevant = relevant and ("phpinfo()" in low or "php version" in low)
            elif path == "/backup.zip": relevant = relevant and (body.startswith("PK") or "zip" in resp.headers.get("Content-Type", "").lower())
            elif path in ("/swagger.json", "/openapi.json"): relevant = relevant and any(x in low for x in ("openapi", "swagger", '"paths"'))
            if relevant:
                count += 1
                report.append(f"[À EXAMINER — risque {severity}] {path} répond HTTP {status} : {description}. Faux positif possible.")
            elif status in (401, 403):
                report.append(f"[PROTÉGÉ] {path} répond HTTP {status}.")
            else:
                report.append(f"[NON DÉTECTÉ] {path} répond HTTP {status}.")
        finally:
            resp.close()
    if not count:
        report.append("Aucune ressource de cette liste n'a été confirmée comme exposée.")
    report.append("La liste est limitée et ne constitue pas une recherche exhaustive.")
    return report




def _active_sqli_xss_checks(session, page_url):
    """Sondes SQLi/XSS limitées, avec répétitions pour réduire les faux positifs."""
    report = ["", "11. SONDAGES ACTIFS SQLi / XSS (LIMITÉS)"]
    parsed = urlparse(page_url)
    params = parse_qsl(parsed.query, keep_blank_values=True)

    if not params:
        return report + [
            "[NON TESTABLE] Aucun paramètre GET dans cette URL.",
            "Les formulaires POST, cookies et paramètres JavaScript ne sont pas testés."
        ]

    params = params[:5]
    report.append(f"Paramètres examinés : {len(params)} maximum 5.")
    report.append(
        "Comparaisons répétées ; les différences de longueur seules ne confirment pas une SQLi."
    )

    for index, (name, original_value) in enumerate(params):
        # Référence répétée pour estimer la variabilité naturelle de la page.
        base_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        baseline_samples = []

        for attempt in range(2):
            result, error, _ = _sqli_fetch(session, base_url)
            if result is None:
                report.append(
                    f"[NON VÉRIFIÉ] Paramètre {name!r} : référence inaccessible ({error})."
                )
                break
            baseline_samples.append(result)
            time.sleep(0.15)

        if len(baseline_samples) != 2:
            continue

        baseline_statuses = [item[0] for item in baseline_samples]
        baseline_bodies = [item[1] for item in baseline_samples]
        baseline_similarity = _sqli_similarity(
            baseline_bodies[0], baseline_bodies[1]
        )

        if baseline_statuses[0] != baseline_statuses[1]:
            report.append(
                f"[INDICE NON CONCLUANT SQLi] {name!r} : "
                "le statut HTTP de référence varie entre deux requêtes."
            )
        elif baseline_similarity < 0.85:
            report.append(
                f"[INDICE NON CONCLUANT SQLi] {name!r} : "
                "le contenu de référence est instable ; comparaison peu fiable."
            )

        baseline_status = baseline_statuses[0]
        baseline_body = baseline_bodies[-1]

        # 1. Sonde par apostrophe : un écart seul n'est jamais une confirmation.
        sql_url = _sqli_probe_url(
            parsed, params, index, name, original_value + "'"
        )
        sql_result, sql_error, _ = _sqli_fetch(session, sql_url)

        if sql_result is None:
            report.append(
                f"[NON VÉRIFIÉ] Sonde apostrophe sur {name!r} : {sql_error}"
            )
        else:
            sql_status, sql_body = sql_result
            markers = [
                marker for marker in SQL_ERROR_MARKERS
                if marker in sql_body.lower()
            ]

            if markers:
                report.append(
                    f"[SUSPICION SQLi] {name!r} : marqueur d'erreur SQL "
                    f"potentiellement visible ({', '.join(markers[:3])}). "
                    "Confirmer manuellement."
                )
            elif sql_status >= 500 and baseline_status < 500:
                report.append(
                    f"[SUSPICION FAIBLE SQLi] {name!r} : "
                    f"la sonde provoque HTTP {sql_status} contre "
                    f"{baseline_status} en référence. "
                    "Une erreur serveur ne prouve pas une SQLi."
                )
            elif sql_status != baseline_status:
                report.append(
                    f"[INDICE NON CONCLUANT SQLi] {name!r} : "
                    f"statut HTTP différent ({baseline_status} → {sql_status})."
                )

        # 2. Comparaison booléenne : deux répétitions par variante.
        # Ces sondes ne lisent ni n'extraient de données.
        if original_value.strip().isdigit():
            true_value = original_value + " AND 1=1"
            false_value = original_value + " AND 1=2"
        else:
            true_value = original_value + "' AND '1'='1"
            false_value = original_value + "' AND '1'='2"

        probe_samples = {"true": [], "false": []}
        probe_errors = []

        for label, value in (
            ("true", true_value),
            ("false", false_value),
        ):
            probe_url = _sqli_probe_url(
                parsed, params, index, name, value
            )

            for attempt in range(2):
                result, error, _ = _sqli_fetch(session, probe_url)
                if result is None:
                    probe_errors.append(error)
                    break

                probe_samples[label].append(result)
                time.sleep(0.15)

        true_samples = probe_samples["true"]
        false_samples = probe_samples["false"]

        if len(true_samples) != 2 or len(false_samples) != 2:
            report.append(
                f"[NON VÉRIFIÉ] SQLi différentielle sur {name!r} : "
                "au moins une requête n'a pas abouti."
            )
        else:
            true_statuses = [x[0] for x in true_samples]
            false_statuses = [x[0] for x in false_samples]
            true_bodies = [x[1] for x in true_samples]
            false_bodies = [x[1] for x in false_samples]

            # Une variante doit donner des résultats répétables.
            true_stability = _sqli_similarity(
                true_bodies[0], true_bodies[1]
            )
            false_stability = _sqli_similarity(
                false_bodies[0], false_bodies[1]
            )

            # Compare les réponses aux références, plutôt que leur seule longueur.
            true_vs_base = _sqli_similarity(
                baseline_body, true_bodies[-1]
            )
            false_vs_base = _sqli_similarity(
                baseline_body, false_bodies[-1]
            )

            stable = (
                baseline_similarity >= 0.85
                and true_statuses[0] == true_statuses[1]
                and false_statuses[0] == false_statuses[1]
                and true_stability >= 0.90
                and false_stability >= 0.90
            )

            clear_difference = (
                true_statuses[-1] != false_statuses[-1]
                or abs(true_vs_base - false_vs_base) >= 0.20
            )

            true_matches_baseline_better = (
                true_vs_base >= false_vs_base + 0.20
            )

            if stable and clear_difference and true_matches_baseline_better:
                report.append(
                    f"[SUSPICION SQLi — DIFFÉRENTIELLE] {name!r} : "
                    "la condition vraie ressemble nettement plus à la "
                    "référence que la condition fausse, de façon répétable. "
                    "Vérification manuelle nécessaire."
                )
            elif not stable:
                report.append(
                    f"[INDICE NON CONCLUANT SQLi] {name!r} : "
                    "réponses instables ou statuts variables ; "
                    "le scanner ne peut pas isoler un effet fiable."
                )
            elif clear_difference:
                report.append(
                    f"[INDICE NON CONCLUANT SQLi] {name!r} : "
                    "les variantes diffèrent, mais le profil attendu "
                    "n'est pas suffisamment établi."
                )
            else:
                report.append(
                    f"[NON DÉTECTÉ] SQLi différentielle sur {name!r} : "
                    "aucun écart répétable suffisamment net. "
                    "Cela n'exclut pas une vulnérabilité."
                )

        # 3. Marqueur XSS inerte : aucun JavaScript exécutable.
        marker = f"CYBERAUDIT_XSS_PROBE_{index + 1}_7F3A"
        xss_url = _sqli_probe_url(
            parsed, params, index, name, original_value + f"<{marker}>"
        )
        xss_result, xss_error, _ = _sqli_fetch(session, xss_url)

        if xss_result is None:
            report.append(f"[NON VÉRIFIÉ] XSS sur {name!r} : {xss_error}")
        else:
            _, xss_body = xss_result
            raw_tag = f"<{marker}>".lower() in xss_body.lower()

            if raw_tag:
                report.append(
                    f"[SUSPICION XSS RÉFLÉCHIE] {name!r} : "
                    "marqueur inerte renvoyé comme balise brute. "
                    "Examiner le contexte HTML avant de conclure."
                )
            elif marker.lower() in xss_body.lower():
                report.append(
                    f"[INFORMATION XSS] {name!r} : marqueur réfléchi, "
                    "mais balise brute non détectée. Vérifier l'encodage."
                )
            else:
                report.append(
                    f"[NON DÉTECTÉ] XSS réfléchie par cette sonde sur {name!r}."
                )

        time.sleep(0.2)

    report.append(
        "Limites : GET uniquement, paramètres déjà présents, corps limité à "
        "100 Ko. Les répétitions réduisent certains faux positifs mais ne "
        "prouvent pas qu'une vulnérabilité est présente ou absente."
    )
    return report



class _LinkExtractor(HTMLParser):
    """Extrait uniquement les liens de navigation et actions de formulaires GET."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag.lower() == "area" and attrs.get("href"):
            self.links.append(attrs["href"])
        # On ne soumet jamais les formulaires. Les actions GET sont simplement
        # découvertes, sans valeurs de champs ni envoi de données.
        elif tag.lower() == "form" and attrs.get("method", "get").lower() == "get" and attrs.get("action"):
            self.links.append(attrs["action"])


def _same_origin(candidate, origin):
    try:
        a, b = urlparse(candidate), urlparse(origin)
        default_a = 80 if a.scheme.lower() == "http" else 443 if a.scheme.lower() == "https" else None
        default_b = 80 if b.scheme.lower() == "http" else 443 if b.scheme.lower() == "https" else None
        return (a.scheme.lower() == b.scheme.lower()
                and (a.hostname or "").lower() == (b.hostname or "").lower()
                and (a.port or default_a) == (b.port or default_b))
    except ValueError:
        return False


def _crawl_and_test_sqli_xss(session, start_url, max_pages=20):
    """Explore un nombre borné de pages internes et sonde les URL avec paramètres.

    GET uniquement, origine identique, pas de soumission de formulaire, pas de
    JavaScript, pas de payload temporel et aucune tentative d'authentification.
    """
    report = ["", "11. EXPLORATION INTERNE ET SONDAGES SQLi / XSS",
              f"Limite d'exploration : {max_pages} URL ; même origine uniquement ; requêtes GET.",
              "Les formulaires ne sont pas soumis. Les pages derrière une connexion et les routes JavaScript peuvent manquer."]
    queue = [urldefrag(start_url)[0]]
    seen = set()
    query_urls = []
    skipped = 0
    static_ext = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js", ".ico", ".pdf", ".zip", ".woff", ".woff2", ".ttf", ".mp4", ".mp3")

    while queue and len(seen) < max_pages:
        candidate = urldefrag(queue.pop(0))[0]
        parsed = urlparse(candidate)
        if candidate in seen:
            continue
        if not _same_origin(candidate, start_url) or parsed.username or parsed.password:
            skipped += 1
            continue
        if parsed.path.lower().endswith(static_ext):
            continue
        valid, reason = validate_url(candidate)
        if not valid:
            report.append(f"[NON VÉRIFIÉ] URL ignorée {candidate} : {reason}")
            continue
        seen.add(candidate)
        # Petit délai entre pages pour limiter la charge sur le serveur audité.
        if len(seen) > 1:
            time.sleep(0.2)
        response, error, body = _request(session, candidate, read_body=True, limit=100_000)
        if response is None:
            report.append(f"[NON VÉRIFIÉ] Exploration de {candidate} : {error}")
            continue
        try:
            if response.status_code in REDIRECT_CODES and response.headers.get("Location"):
                redirected = urljoin(candidate, response.headers["Location"])
                if _same_origin(redirected, start_url) and redirected not in seen:
                    queue.append(redirected)
            content_type = response.headers.get("Content-Type", "").lower()
            if "text/html" in content_type or "application/xhtml" in content_type or (not content_type and "<html" in body[:1000].lower()):
                parser = _LinkExtractor()
                try:
                    parser.feed(body)
                except Exception:
                    pass
                for href in parser.links:
                    href = (href or "").strip()
                    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                        continue
                    absolute = urldefrag(urljoin(candidate, href))[0]
                    if _same_origin(absolute, start_url) and absolute not in seen and absolute not in queue:
                        queue.append(absolute)
                    elif not _same_origin(absolute, start_url):
                        skipped += 1
            if parse_qsl(parsed.query, keep_blank_values=True):
                query_urls.append(candidate)
        finally:
            response.close()

    report.append(f"Pages/URL explorées : {len(seen)} sur {max_pages} maximum.")
    report.append(f"URL contenant des paramètres GET découvertes : {len(query_urls)}.")
    # Déduplique les variantes d'une même route qui ne changent que la valeur.
    unique_query_urls = []
    route_signatures = set()
    for candidate_url in query_urls:
        candidate_parsed = urlparse(candidate_url)
        param_names = tuple(sorted(name for name, _ in parse_qsl(candidate_parsed.query, keep_blank_values=True)))
        signature = (candidate_parsed.path.rstrip('/') or '/', param_names)
        if signature not in route_signatures:
            route_signatures.add(signature)
            unique_query_urls.append(candidate_url)
    report.append(f"Surfaces distinctes après déduplication chemin/paramètres : {len(unique_query_urls)}.")
    if queue:
        report.append(f"[À EXAMINER] Limite atteinte : {len(queue)} URL interne(s) supplémentaire(s) non explorée(s).")
    if skipped:
        report.append(f"Liens externes ou hors périmètre ignorés : {skipped}.")
    if not unique_query_urls:
        report.append("[NON TESTABLE] Aucune URL avec paramètre GET n'a été découverte. Cela ne prouve pas l'absence de SQLi.")
        report.append("Diagnostic : le scanner ne modifie que des paramètres GET existants. Si le laboratoire utilise un formulaire POST, un cookie, une route JavaScript ou une zone authentifiée, cette version ne peut pas tester son point vulnérable.")
    else:
        for page_index, page_url in enumerate(unique_query_urls[:max_pages], 1):
            report.append(f"\n--- Surface testée {page_index}/{min(len(unique_query_urls), max_pages)} : {page_url} ---")
            report.extend(_active_sqli_xss_checks(session, page_url))
    report.append("Limites : sondes indicatives sur paramètres GET existants uniquement ; comparaison booléenne sans extraction de données, formulaires non soumis, POST/API, contenu JavaScript et zones authentifiées non couverts. Un résultat négatif ne prouve pas l'absence de faille.")
    return report


def _check_anonymous_access(session, base_url, resource_paths=None):
    """Vérifie des chemins courants sans session, ou une liste fournie par le code."""
    report = ["", "12. CONTRÔLE D'ACCÈS ANONYME (GET UNIQUEMENT)"]
    paths = [p.strip() for p in (DEFAULT_PRIVATE_PATHS if resource_paths is None else resource_paths) if p.strip()]
    if not paths:
        return report + ["[NON CONFIGURÉ] Aucun chemin de ressource à vérifier.",
                         "Ce contrôle ne confirme pas les IDOR ; il vérifie uniquement l'accès sans authentification."]
    base = urlparse(base_url)
    report.append(f"Chemins configurés dans le code : {min(len(paths), 25)} maximum 25.")
    for path in paths[:25]:
        target = urljoin(base_url.rstrip('/') + '/', path)
        parsed_target = urlparse(target)
        base_port = base.port or (80 if base.scheme.lower() == "http" else 443)
        target_port = parsed_target.port or (80 if parsed_target.scheme.lower() == "http" else 443)
        if (parsed_target.scheme.lower() != base.scheme.lower()
                or (parsed_target.hostname or "").lower() != (base.hostname or "").lower()
                or target_port != base_port
                or parsed_target.username or parsed_target.password):
            report.append(f"[REFUSÉ] {path!r} : la destination doit rester sur la même origine HTTP/HTTPS.")
            continue
        resp, error, body = _request(session, target, read_body=True, limit=20_000)
        if resp is None:
            report.append(f"[NON VÉRIFIÉ] {path!r} : {error}")
            continue
        try:
            status = resp.status_code
            if status in (401, 403):
                report.append(f"[PROTECTION APPARENTE] {path!r} répond HTTP {status} sans authentification.")
            elif status in (200, 206):
                report.append(f"[À EXAMINER] {path!r} répond HTTP {status} sans authentification ({len(body)} caractères lus). Vérifier que la ressource est réellement privée.")
            elif status in (301, 302, 303, 307, 308):
                report.append(f"[À EXAMINER] {path!r} redirige sans authentification vers {resp.headers.get('Location', '(destination non communiquée)')}.")
            else:
                report.append(f"[NON CONCLUANT] {path!r} répond HTTP {status}.")
        finally:
            resp.close()
    report.append("Ce test ne compare pas deux identités : une IDOR exige des comptes de test distincts et des objets autorisés.")
    return report


def audit_site(url: str, active_tests: bool = False, access_paths=None) -> str:
    """Audit web prudent ; les chemins privés par défaut sont définis dans ce fichier."""
    url = url.strip()
    valid, reason = validate_url(url)
    if not valid:
        return f"CYBERAUDIT DESKTOP — RAPPORT\n{'=' * 45}\nURL refusée : {reason}"
    initial_scheme = urlparse(url).scheme.lower()
    report = ["CYBERAUDIT DESKTOP — RAPPORT", "=" * 45,
              f"Date UTC : {datetime.now(timezone.utc).isoformat()}", f"URL initiale : {url}",
              "Périmètre : contrôles non destructifs sur une URL HTTP/HTTPS publique.",
              "Utilisez uniquement sur un site que vous possédez ou êtes autorisé à tester."]
    initial_host = (urlparse(url).hostname or "").lower().rstrip(".")
    if initial_host == "portswigger.net" or initial_host.endswith(".portswigger.net"):
        report.extend(["", "[DIAGNOSTIC] L'URL cible est sur le site pédagogique PortSwigger, pas sur une instance de laboratoire dédiée.",
                       "Pour tester une vulnérabilité de laboratoire, lance le laboratoire depuis Web Security Academy puis saisis l'URL de l'instance, généralement sur *.web-security-academy.net.",
                       "La page pédagogique elle-même n'est pas censée présenter la vulnérabilité décrite dans le laboratoire."])
    elif initial_host.endswith(".web-security-academy.net"):
        report.extend(["", "[DIAGNOSTIC] Hôte de laboratoire Web Security Academy détecté.",
                       "Les tests actifs de CyberAudit couvrent seulement les URL GET et paramètres déjà découverts ; les formulaires POST, cookies, JavaScript côté client et parcours authentifiés ne sont pas couverts."])
    report.extend(["", "1. CONNEXION ET REDIRECTIONS"])
    if initial_scheme == "http":
        report.append("[RISQUE] URL initiale en HTTP : les échanges ne sont pas chiffrés.")
    current, chain, response, body = url, [], None, ""
    try:
        with requests.Session() as session:
            session.trust_env = False
            for step in range(MAX_REDIRECTS + 1):
                response, error, _ = _request(session, current)
                if response is None:
                    report.append("Échec de connexion : " + error)
                    return "\n".join(report)
                if response.status_code not in REDIRECT_CODES or not response.headers.get("Location"):
                    body = _read_limited(response)
                    break
                next_url = urljoin(current, response.headers["Location"])
                chain.append(f"{response.status_code} : {current} -> {next_url}")
                response.close()
                response = None
                if step >= MAX_REDIRECTS:
                    report.append(f"Limite de {MAX_REDIRECTS} redirections atteinte.")
                    return "\n".join(report)
                current = next_url
            report.append(f"URL finale : {current}")
            report.append("Chaîne suivie :")
            report.extend(["  " + item for item in chain] if chain else ["  Aucune redirection."])
            report.append(f"Code HTTP final : {response.status_code}")
            final_scheme = urlparse(current).scheme.lower()
            if final_scheme == "https":
                report.append("[OK] Connexion HTTPS avec validation du certificat : réussie.")
            else:
                report.append("[RISQUE] La page finale utilise HTTP : les échanges restent non chiffrés.")
            if initial_scheme == "http" and final_scheme == "https":
                report.append("[OK] L'URL HTTP aboutit à HTTPS après redirection.")
            elif initial_scheme == "https" and final_scheme == "http":
                report.append("[RISQUE] Déclassement HTTPS vers HTTP détecté dans la chaîne de redirection.")
            elif initial_scheme == "http" and final_scheme == "http":
                report.append("[SUSPICION] Aucune redirection finale vers HTTPS n'a été observée.")
            report.extend(["", "2. EN-TÊTES DE SÉCURITÉ"])
            for header, desc in SECURITY_HEADERS.items():
                value = response.headers.get(header)
                if header == "Strict-Transport-Security" and final_scheme != "https":
                    report.append("[NON APPLICABLE] HSTS doit être envoyé par une réponse HTTPS.")
                else:
                    report.append(f"[PRÉSENT] {header}: {value} — {desc}" if value else f"[ABSENT] {header} — {desc}")
            csp = response.headers.get("Content-Security-Policy", "").lower()
            if "unsafe-inline" in csp:
                report.append("[À EXAMINER] CSP contient unsafe-inline, ce qui peut réduire sa protection contre certaines XSS.")
            report.extend(_check_cookies(response))
            report.extend(["", "4. INFORMATIONS HTTP", f"Content-Type : {response.headers.get('Content-Type', 'non communiqué')}"])
            hostname = urlparse(current).hostname
            if hostname and final_scheme == "https":
                report.extend(get_tls_certificate_report(hostname))
                report.extend(check_tls_protocols(hostname))
            else:
                report.extend(["", "5. CERTIFICAT TLS DÉTAILLÉ", "[NON APPLICABLE] La page finale utilise HTTP ; aucun certificat TLS n'est utilisé pour cette connexion."])
                report.extend(["", "6. PROTOCOLES TLS", "[NON APPLICABLE] La page finale utilise HTTP."])
            report.extend(_check_technology(body, response))
            report.extend(_check_passive_sqli_xss(body))
            report.extend(_check_exposed_paths(session, current))
            if active_tests:
                report.extend(_crawl_and_test_sqli_xss(session, current, max_pages=20))
            else:
                report.extend(["", "11. EXPLORATION ET SONDAGES ACTIFS SQLi / XSS", "[NON EXÉCUTÉ] Activez l'option d'exploration et de tests actifs dans l'interface. L'exploration est limitée à 20 URL internes et teste uniquement les paramètres GET existants."])
            report.extend(_check_anonymous_access(session, current, access_paths))
            report.extend(["", "13. CONTRÔLES NON COUVERTS / LIMITES",
                "[NON TESTÉ] IDOR complète et comparaison entre utilisateurs : nécessitent deux comptes de test distincts et des ressources contrôlées.",
                "[NON TESTÉ] Contournement d'authentification et flux de session : nécessitent des scénarios adaptés.",
                "[NON TESTÉ] Dépendances vulnérables : nécessite un inventaire de dépendances et une base d'avis de sécurité.",
                "[NON TESTÉ] XSS stockée, formulaires POST, JSON/API et pages nécessitant une connexion : non couverts par les sondes GET limitées.",
                "[NON TESTÉ] Versions logicielles vulnérables : les signatures ne suffisent pas à confirmer une version.",
                "", "FIN DU RAPPORT", "Un résultat négatif ne prouve pas l'absence de vulnérabilité ; les indices doivent être vérifiés manuellement."])
            return "\n".join(report)
    finally:
        if response is not None:
            response.close()
