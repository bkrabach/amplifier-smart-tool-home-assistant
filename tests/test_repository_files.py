from __future__ import annotations

import io
import re
import tarfile
import tomllib
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

import pytest


ROOT = Path(__file__).parents[1]
DOCUMENTS = (
    "README.md",
    "CONTRIBUTING.md",
    "AGENTS.md",
    "SECURITY.md",
    "SUPPORT.md",
    "CODE_OF_CONDUCT.md",
    "docs/getting-started.md",
    "docs/usage.md",
    "docs/architecture.md",
    "docs/troubleshooting.md",
    "docs/VISION.md",
    "contracts/home-assistant.v1.md",
    "src/ha_analysis/SMART_TOOL.md",
)
STANDARD_FILES = (
    *DOCUMENTS[:6],
    ".editorconfig",
    ".gitattributes",
    ".github/CODEOWNERS",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/workflows/ci.yml",
)
TEST_FILES = tuple(path.relative_to(ROOT).as_posix() for path in (ROOT / "tests").glob("*.py"))
REQUIRED_SDIST_FILES = frozenset(
    DOCUMENTS
    + STANDARD_FILES
    + ("LICENSE", ".gitignore", "pyproject.toml", "smart-tool.json", "uv.lock")
    + TEST_FILES
)
LINK = re.compile(r"\[[^\]]*]\(([^)]+)\)")
CANONICAL_URL = re.compile(
    r"https://github\.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/"
    r"[^\s<>()\[\]{}\"']+"
)
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.MULTILINE)
PUBLIC_DOCUMENTS = (*DOCUMENTS, ".github/PULL_REQUEST_TEMPLATE.md")


def test_required_repository_files_are_nonempty() -> None:
    required_files = (*STANDARD_FILES, *DOCUMENTS[6:])
    missing = [path for path in required_files if not (ROOT / path).is_file()]
    assert not missing, f"missing repository files: {', '.join(missing)}"
    empty = [path for path in required_files if not (ROOT / path).read_text().strip()]
    assert not empty, f"empty repository files: {', '.join(empty)}"


def test_readme_has_auditable_contributing_and_trademarks_sections() -> None:
    readme = (ROOT / "README.md").read_text()
    assert re.search(r"^## Contributing\s*$", readme, re.MULTILINE)
    assert re.search(r"^## Trademarks\s*$", readme, re.MULTILINE)
    assert "synthetic" in (ROOT / "src/ha_analysis/SMART_TOOL.md").read_text().lower()


def test_sdist_allowlist_is_explicit_and_covers_every_required_file() -> None:
    with (ROOT / "pyproject.toml").open("rb") as project_file:
        include = tomllib.load(project_file)["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]

    included = set(include)
    expected_explicit = {f"/{path}" for path in REQUIRED_SDIST_FILES if not path.startswith("tests/")}
    missing = sorted(expected_explicit - included)
    assert not missing, f"source distribution allowlist is missing: {', '.join(missing)}"
    assert "/tests/*.py" in included
    assert "/src/ha_analysis/*.py" in included
    assert "/src/ha_analysis/SMART_TOOL.md" in included
    assert "/docs/*.md" not in included


def test_document_links_resolve() -> None:
    for relative_path in PUBLIC_DOCUMENTS:
        _validate_document_links(ROOT / relative_path, ROOT)


def test_link_scanner_handles_canonical_urls_and_anchors(tmp_path: Path) -> None:
    document = tmp_path / "document.md"
    document.write_text(
        "https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/README.md.\n"
        "[section](https://github.com/bkrabach/amplifier-smart-tool-home-assistant/"
        "blob/main/README.md#contributing)\n"
        "[encoded](https://github.com/bkrabach/amplifier-smart-tool-home-assistant/"
        "blob/main/docs%2Fusage.md)\n"
    )

    _validate_document_links(document, ROOT)


@pytest.mark.parametrize(
    "url, message",
    (
        (
            "https://github.com/bkrabach/amplifier-smart-tool-home-assistant/"
            "blob/main/missing.md",
            "missing target",
        ),
        (
            "https://github.com/bkrabach/amplifier-smart-tool-home-assistant/"
            "blob/main/README.md#missing-section",
            "missing anchor",
        ),
        (
            "https://github.com/bkrabach/amplifier-smart-tool-home-assistant/"
            "blob/main/%2e%2e/README.md",
            "leaves repository",
        ),
    ),
)
def test_link_scanner_rejects_unsafe_or_invalid_canonical_urls(
    tmp_path: Path, url: str, message: str
) -> None:
    document = tmp_path / "document.md"
    document.write_text(f"{url}\n")

    with pytest.raises(AssertionError, match=message):
        _validate_document_links(document, ROOT)


def test_relative_link_checker_rejects_a_missing_target(tmp_path: Path) -> None:
    document = tmp_path / "document.md"
    document.write_text("[missing](missing.md)\n")

    with pytest.raises(AssertionError, match="missing target"):
        _validate_document_links(document, tmp_path)


@pytest.mark.parametrize(
    "absent",
    (
        ".github/workflows/ci.yml",
        "docs/VISION.md",
        "contracts/home-assistant.v1.md",
    ),
)
def test_validate_sdist_rejects_missing_required_member(tmp_path: Path, absent: str) -> None:
    archive = tmp_path / "package.tar.gz"
    _write_test_sdist(archive, absent=absent)

    with pytest.raises(AssertionError, match="source distribution is missing"):
        validate_sdist(archive)


@pytest.mark.parametrize(
    "empty",
    (
        ".github/workflows/ci.yml",
        "tests/test_repository_files.py",
        "docs/VISION.md",
        "contracts/home-assistant.v1.md",
    ),
)
def test_validate_sdist_rejects_empty_required_member(tmp_path: Path, empty: str) -> None:
    archive = tmp_path / "package.tar.gz"
    _write_test_sdist(archive, empty=empty)

    with pytest.raises(AssertionError, match="empty required members"):
        validate_sdist(archive)


def validate_sdist(archive: Path) -> None:
    files: dict[str, int] = {}
    roots: set[str] = set()
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            name = PurePosixPath(member.name)
            assert not name.is_absolute() and ".." not in name.parts, (
                f"unsafe source distribution member: {member.name}"
            )
            if member.issym() or member.islnk():
                raise AssertionError(f"source distribution contains a link: {member.name}")
            if member.isdir():
                continue
            assert member.isfile(), f"unexpected source distribution member: {member.name}"
            assert len(name.parts) > 1, f"source distribution member lacks a package root: {member.name}"
            roots.add(name.parts[0])
            files[PurePosixPath(*name.parts[1:]).as_posix()] = member.size

    assert len(roots) == 1, "source distribution must have one package root"
    missing = sorted(REQUIRED_SDIST_FILES - files.keys())
    assert not missing, f"source distribution is missing: {', '.join(missing)}"
    empty = sorted(path for path in REQUIRED_SDIST_FILES if files[path] == 0)
    assert not empty, f"source distribution has empty required members: {', '.join(empty)}"


def _validate_document_links(document: Path, root: Path) -> None:
    content = document.read_text()
    for match in LINK.finditer(content):
        target = match.group(1).split(maxsplit=1)[0].strip("<>")
        if not target or target.startswith(("http://", "https://", "mailto:")):
            continue
        _validate_target(document, unquote(target), root)
    for url in CANONICAL_URL.findall(content):
        _validate_canonical_url(document, url.rstrip(".,;:!?"), root)


def _validate_canonical_url(document: Path, url: str, root: Path) -> None:
    parsed = urlsplit(url)
    prefix = "/bkrabach/amplifier-smart-tool-home-assistant/blob/main/"
    assert parsed.path.startswith(prefix), f"{document}: invalid canonical URL: {url}"
    target = unquote(parsed.path.removeprefix(prefix))
    if parsed.fragment:
        target = f"{target}#{unquote(parsed.fragment)}"
    _validate_target(document, target, root, base=root)


def _validate_target(document: Path, target: str, root: Path, base: Path | None = None) -> None:
    path, separator, anchor = target.partition("#")
    destination = document if not path else ((base or document.parent) / path).resolve()
    repository = root.resolve()
    assert destination.is_relative_to(repository), f"{document}: link leaves repository: {target}"
    assert destination.is_file(), f"{document}: missing target: {target}"
    if separator:
        assert anchor in _anchors(destination), f"{document}: missing anchor: {target}"


def _anchors(document: Path) -> set[str]:
    counts: dict[str, int] = {}
    anchors: set[str] = set()
    for title in HEADING.findall(document.read_text()):
        anchor = re.sub(r"[^\w\s-]", "", title.lower())
        anchor = re.sub(r"\s+", "-", anchor.strip())
        count = counts.get(anchor, 0)
        counts[anchor] = count + 1
        anchors.add(anchor if count == 0 else f"{anchor}-{count}")
    return anchors


def _write_test_sdist(
    archive: Path, absent: str | None = None, empty: str | None = None
) -> None:
    with tarfile.open(archive, "w:gz") as source:
        for relative_path in sorted(REQUIRED_SDIST_FILES):
            if relative_path == absent:
                continue
            payload = b"" if relative_path == empty else (ROOT / relative_path).read_bytes()
            member = tarfile.TarInfo(f"ha_analysis-0.8.0/{relative_path}")
            member.size = len(payload)
            source.addfile(member, io.BytesIO(payload))