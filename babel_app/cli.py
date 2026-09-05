from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .banner import BABEL_BANNER
from .scenarios import run

console = Console()


def _banner() -> None:
    console.print(f"[bold blue]{BABEL_BANNER}[/bold blue]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD multi-agent confusion — роль-конфузия и транзитивная инъекция цепочки."""


@main.command("test")
@click.argument("url")
@click.option("--chain-to", "url2", default=None,
              help="URL второго агента: включает тест транзитивной инъекции цепочки A1→A2")
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить JSON-находки (контракт пайплайна)")
def test_cmd(url: str, url2: str | None, as_json: str | None) -> None:
    """Проверить агента (роль-конфузия) и, при --chain-to, цепочку (транзитивная инъекция)."""
    d = run(url, url2)
    if as_json:
        Path(as_json).write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")

    # 🔴 rc=2 «не состоялась» ≠ rc=0 «чисто»
    if d["verdict"] == "НЕ ПРОВЕРЕНО":
        console.print(f"[yellow]НЕ ПРОВЕРЕНО[/yellow]: {d['not_proven']}")
        raise SystemExit(2)

    t = Table(title=f"babel: {url}" + (f"  →  {url2}" if url2 else ""))
    t.add_column("класс"); t.add_column("вердикт"); t.add_column("почему")
    for f in d["findings"]:
        цвет = {"ПРОВАЛ": "red", "НЕ ПРОВЕРЕНО": "yellow"}.get(f["verdict"], "green")
        t.add_row(f["класс"], f"[{цвет}]{f['verdict']}[/{цвет}]", f["почему"])
    console.print(t)
    цвет = "red" if d["verdict"] == "ПРОВАЛ" else "green"
    console.print(f"Вердикт: [{цвет}]{d['verdict']}[/{цвет}] — {d['почему']}")

    if d["verdict"] == "ПРОВАЛ":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
