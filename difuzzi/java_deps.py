"""The Java-side dependencies of the Java backend (Jazzer, JaCoCo, ASM): where they are, and downloading
them on first use.

Location, in order: $DIFUZZI_JAVA_DEPS; a third_party/ folder next to the package (a source checkout);
otherwise ~/.cache/difuzzi/java-deps (or $XDG_CACHE_HOME/difuzzi/java-deps), filled on first use.

    difuzzi-setup            download them now (e.g. before working offline)
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

JAZZER, JACOCO, ASM = "0.30.0", "0.8.13", "9.7.1"
MAVEN = "https://repo1.maven.org/maven2"
JARS = {
    "jazzer-api.jar": f"{MAVEN}/com/code-intelligence/jazzer-api/{JAZZER}/jazzer-api-{JAZZER}.jar",
    "jacocoagent.jar": f"{MAVEN}/org/jacoco/org.jacoco.agent/{JACOCO}/org.jacoco.agent-{JACOCO}-runtime.jar",
    "jacococli.jar": f"{MAVEN}/org/jacoco/org.jacoco.cli/{JACOCO}/org.jacoco.cli-{JACOCO}-nodeps.jar",
    "asm.jar": f"{MAVEN}/org/ow2/asm/asm/{ASM}/asm-{ASM}.jar",
}
REQUIRED = ["jazzer/jazzer", "jazzer/jazzer_standalone.jar", *JARS]


def _jazzer_archive() -> str:
    system, machine = platform.system(), platform.machine().lower()
    if system == "Linux":
        name = "linux-arm64" if machine in ("aarch64", "arm64") else "linux-x86-64"
    elif system == "Darwin":
        name = "macos"
    elif system == "Windows":
        name = "windows"
    else:
        raise RuntimeError(f"Jazzer is not available for {system}")
    return f"https://github.com/CodeIntelligenceTesting/jazzer/releases/download/v{JAZZER}/jazzer-{name}.tar.gz"


def location() -> Path:
    if os.environ.get("DIFUZZI_JAVA_DEPS"):
        return Path(os.environ["DIFUZZI_JAVA_DEPS"])
    checkout = Path(__file__).resolve().parent.parent / "third_party"
    if all((checkout / r).exists() for r in REQUIRED):
        return checkout
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return cache / "difuzzi" / "java-deps"


def missing(where: Path = None) -> list:
    where = where or location()
    jazzer = "jazzer/jazzer.exe" if platform.system() == "Windows" else "jazzer/jazzer"
    return [r for r in [jazzer, *REQUIRED[1:]] if not (where / r).exists()]


def _download(url: str, dest: Path, log):
    log(f"  downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as r, tempfile.NamedTemporaryFile(delete=False, dir=dest.parent) as f:
        shutil.copyfileobj(r, f)
    os.replace(f.name, dest)


def ensure(log=lambda m: print(m, file=sys.stderr)) -> Path:
    """The dependency folder, downloading whatever is missing."""
    where = location()
    todo = missing(where)
    if not todo:
        return where
    log(f"Java backend: downloading Jazzer {JAZZER}, JaCoCo {JACOCO} and ASM {ASM} into {where} (once) ...")
    where.mkdir(parents=True, exist_ok=True)
    for name, url in JARS.items():
        if not (where / name).exists():
            _download(url, where / name, log)
    if any(t.startswith("jazzer/") for t in todo):
        archive = where / "jazzer.tar.gz"
        _download(_jazzer_archive(), archive, log)
        (where / "jazzer").mkdir(exist_ok=True)
        with tarfile.open(archive) as tar:
            tar.extractall(where / "jazzer", filter="data") if sys.version_info >= (3, 12) \
                else tar.extractall(where / "jazzer")
        archive.unlink()
    still = missing(where)
    if still:
        raise RuntimeError(f"Java dependencies still missing after download: {', '.join(still)} (in {where})")
    return where


def main():
    where = ensure(log=print)
    print(f"Java dependencies ready in {where}")


if __name__ == "__main__":
    main()
