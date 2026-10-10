import sys
import json
import html
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox, QFileDialog, QCheckBox,
)
from scanner import audit_site



def colored_report_html(report: str) -> str:
    """Convertit le rapport texte en HTML coloré."""
    rendered_lines = []

    for line in report.splitlines():
        safe_line = html.escape(line)
        stripped = line.strip()
        color = "#cbd5e1"
        weight = "normal"

        # Rouge : risques et vulnérabilités confirmées.
        if stripped.startswith((
            "[RISQUE]",
            "[ALERTE]",
            "[VULNÉRABILITÉ CONFIRMÉE]",
            "[ERREUR]",
        )):
            color, weight = "#f87171", "bold"

        # Orange : suspicions et éléments à vérifier.
        elif stripped.startswith((
            "[SUSPICION",
            "[INDICE NON CONCLUANT",
            "[À EXAMINER]",
            "[ABSENT]",
            "[NON VÉRIFIÉ]",
        )):
            color, weight = "#fb923c", "bold"

        # Vert : contrôles positifs.
        elif stripped.startswith(("[OK]", "[PRÉSENT]")):
            color, weight = "#4ade80", "bold"

        # Gris : résultats non concluants ou contrôles non exécutés.
        elif stripped.startswith((
            "[NON DÉTECTÉ]",
            "[NON TESTÉ]",
            "[NON EXÉCUTÉ]",
            "[NON TESTABLE]",
            "[NON CONCLUANT]",
        )):
            color, weight = "#94a3b8", "normal"

        # Bleu : titres et sections.
        elif stripped and (
            stripped.isupper()
            or (stripped[0].isdigit() and ". " in stripped[:5])
        ):
            color, weight = "#38bdf8", "bold"

        rendered_lines.append(
            f'<span style="color:{color};font-weight:{weight};">'
            f'{safe_line}</span>'
        )

    return "\n".join(rendered_lines)


class CyberAuditWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberAudit Desktop")
        self.resize(1100, 720)
        self.last_report = ""
        self.last_url = ""

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        title = QLabel("CYBERAUDIT DESKTOP")
        title.setObjectName("title")
        subtitle = QLabel("Audit web prudent — sécurité HTTP/HTTPS et exploration interne limitée")
        subtitle.setObjectName("subtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(QLabel("URL du site à auditer (uniquement avec autorisation)"))

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://monsite.fr ou http://monsite.fr")
        self.url_input.returnPressed.connect(self.run_audit)
        layout.addWidget(self.url_input)

        self.active_tests = QCheckBox("Explorer jusqu’à 20 URL internes et tester les paramètres GET (SQLi / XSS limitées)")
        self.active_tests.setChecked(False)
        layout.addWidget(self.active_tests)

        buttons = QHBoxLayout()
        self.scan_button = QPushButton("Lancer l'audit")
        self.scan_button.clicked.connect(self.run_audit)
        self.clear_button = QPushButton("Effacer les résultats")
        self.clear_button.clicked.connect(self.clear_results)
        self.export_button = QPushButton("Exporter le rapport")
        self.export_button.clicked.connect(self.export_report)
        self.export_button.setEnabled(False)
        for button in (self.scan_button, self.clear_button, self.export_button):
            buttons.addWidget(button)
        layout.addLayout(buttons)

        self.results = QTextEdit()
        self.results.setReadOnly(True)
        self.results.setPlaceholderText("Les résultats de l'audit apparaîtront ici...")
        layout.addWidget(self.results, 1)

        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #10141c; color: #e5e7eb; font-size: 14px; }
            QLabel#title { color: #38bdf8; font-size: 25px; font-weight: bold; letter-spacing: 2px; }
            QLabel#subtitle { color: #94a3b8; padding-bottom: 8px; }
            QLineEdit, QTextEdit { background-color: #1b2330; color: #f8fafc; border: 1px solid #334155; border-radius: 7px; padding: 10px; }
            QPushButton { background-color: #087ea4; color: white; border: none; border-radius: 7px; padding: 11px 14px; font-weight: bold; }
            QPushButton:hover { background-color: #0ea5e9; }
            QPushButton:disabled { background-color: #334155; color: #94a3b8; }
        """)

    def run_audit(self):
        url = self.url_input.text().strip()
        try:
            parsed = urlparse(url)
            port = parsed.port
        except ValueError:
            QMessageBox.warning(self, "URL invalide", "Vérifie l'adresse saisie.")
            return
        scheme = parsed.scheme.lower()
        expected_port = 80 if scheme == "http" else 443 if scheme == "https" else None
        if (expected_port is None or not parsed.hostname or parsed.username or parsed.password
                or port not in (None, expected_port)):
            QMessageBox.warning(
                self, "URL invalide",
                "Saisis une URL HTTP (port 80) ou HTTPS (port 443) valide."
            )
            return

        answer = QMessageBox.question(
            self, "Autorisation requise",
            "Confirme-tu que tu possèdes ce site ou que tu as l'autorisation de l'auditer ?\n\nLe scan envoie des requêtes HTTP/HTTPS GET. HTTP n'est pas chiffré. Si l'exploration est activée, le logiciel visitera au maximum 20 URL internes et testera les paramètres GET déjà présents. Il ne soumet pas les formulaires, n'exécute aucun JavaScript et ne teste pas les requêtes POST/API. Cela peut générer plusieurs dizaines de requêtes.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        self.scan_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.last_report = ""
        self.last_url = ""
        self.results.setPlainText(f"Audit en cours sur {parsed.hostname}...\nVeuillez patienter.")
        QApplication.processEvents()
        try:
            report = audit_site(url, active_tests=self.active_tests.isChecked())
            self.results.setHtml(
                '<pre style="white-space:pre-wrap;font-family:Consolas,monospace;line-height:1.5;">'
                + colored_report_html(report) + '</pre>'
            )
            self.last_report = report
            self.last_url = url
            has_report = bool(report.strip())
            self.export_button.setEnabled(has_report)
        except Exception as exc:
            self.results.setPlainText(f"Erreur pendant l'audit : {exc}")
        finally:
            self.scan_button.setEnabled(True)

    def export_report(self):
        """Exporte le rapport dans le format choisi dans la boîte de dialogue."""
        if not self.last_report:
            return

        filters = "Rapport HTML (*.html);;Rapport texte (*.txt);;Rapport JSON (*.json)"
        path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Exporter le rapport",
            "rapport_cyberaudit.html",
            filters,
        )
        if not path:
            return

        if "HTML" in selected_filter:
            extension = ".html"
            export_format = "html"
        elif "JSON" in selected_filter:
            extension = ".json"
            export_format = "json"
        else:
            extension = ".txt"
            export_format = "txt"

        if not path.lower().endswith(extension):
            path += extension

        try:
            if export_format == "txt":
                Path(path).write_text(self.last_report, encoding="utf-8")
            elif export_format == "html":
                safe_report = colored_report_html(self.last_report)
                safe_url = html.escape(self.last_url)
                content = f'''<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport CyberAudit Desktop</title><style>
body {{ background:#10141c;color:#e5e7eb;font-family:Arial,sans-serif;margin:0;padding:32px; }}
main {{ max-width:1000px;margin:auto; }} h1 {{ color:#38bdf8; }} .url {{ color:#94a3b8;overflow-wrap:anywhere; }}
pre {{ white-space:pre-wrap;overflow-wrap:anywhere;background:#1b2330;border:1px solid #334155;border-radius:8px;padding:20px;line-height:1.6; }}
</style></head><body><main><h1>CYBERAUDIT DESKTOP</h1><p class="url">URL auditée : {safe_url}</p><pre>{safe_report}</pre></main></body></html>'''
                Path(path).write_text(content, encoding="utf-8")
            else:
                data = {
                    "application": "CyberAudit Desktop",
                    "url": self.last_url,
                    "date_utc": datetime.now(timezone.utc).isoformat(),
                    "rapport": self.last_report,
                }
                Path(path).write_text(
                    json.dumps(data, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            QMessageBox.information(
                self, "Export terminé",
                f"Le rapport {export_format.upper()} a été exporté avec succès."
            )
        except OSError as exc:
            QMessageBox.critical(self, "Erreur d'export", str(exc))

    def clear_results(self):
        self.results.clear()
        self.last_report = ""
        self.last_url = ""
        self.export_button.setEnabled(False)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CyberAuditWindow()
    window.show()
    sys.exit(app.exec())
