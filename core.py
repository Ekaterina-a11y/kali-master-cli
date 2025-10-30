import json, os, pyperclip, shutil
from pathlib import Path
from fuzzywuzzy import fuzz
from rich.console import Console
from rich.table import Table
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter

ROOT = Path(__file__).parent
console = Console()

def load_data(file):
    with open(ROOT/"data"/file, encoding="utf-8") as f:
        return json.load(f)

TOOLS = load_data("tools.json")
DORKS = load_data("dorks.json")
WORDLISTS = load_data("wordlists.json")

def fuzzy_search(query, threshold=60):
    results = []
    for name, meta in TOOLS.items():
        score = max(
            fuzz.partial_ratio(query.lower(), name.lower()),
            *[fuzz.partial_ratio(query.lower(), cmd.lower()) for cmd in meta["commands"].values()],
            *[fuzz.partial_ratio(query.lower(), tag.lower()) for tag in meta.get("tags", [])]
        )
        if score >= threshold:
            results.append((name, meta, score))
    return sorted(results, key=lambda x: x[2], reverse=True)

def interactive_cli():
    names = list(TOOLS.keys())
    completer = WordCompleter(names + ["wordlist", "dork", "export"], ignore_case=True)
    while True:
        query = prompt("🔍 kali-master> ", completer=completer).strip()
        if query in {"q", "quit", "exit"}:
            break
        if query == "export":
            export_html()
            continue
        res = fuzzy_search(query)
        if not res:
            console.print("[red]Aucun résultat.[/red]")
            continue
        pick_and_copy(res)

def pick_and_copy(results):
    table = Table(title="Résultats")
    table.add_column("#", style="bold cyan")
    table.add_column("Outil", style="green")
    table.add_column("Commande", style="white")
    for idx, (name, meta, _) in enumerate(results[:5], 1):
        cmd = list(meta["commands"].values())[0]
        table.add_row(str(idx), name, cmd)
    console.print(table)
    try:
        pick = int(console.input("[bold]Copier # > ")) - 1
        cmd = list(results[pick][1]["commands"].values())[0]
        pyperclip.copy(cmd)
        console.print("[green]Copié ! ✅[/green]")
    except Exception:
        console.print("[red]Invalide.[/red]")

def export_html(filename="report.html"):
    html = "<html><head><meta charset='utf-8'><title>Kali Master Report</title></head><body>"
    for name, meta in TOOLS.items():
        html += f"<h2>{name}</h2><ul>"
        for desc, cmd in meta["commands"].items():
            html += f"<li><b>{desc}</b><br><code>{cmd}</code></li>"
        html += "</ul>"
    html += "</body></html>"
    Path(filename).write_text(html, encoding="utf-8")
    console.print(f"[green]Exporté : {filename} 📄[/green]")
