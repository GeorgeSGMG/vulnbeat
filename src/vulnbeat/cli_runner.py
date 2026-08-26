import subprocess

CLI_TIMEOUT_SECONDS = 120


def run_cli(command: list[str], timeout: int = CLI_TIMEOUT_SECONDS) -> str:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f"{command[0]} failed (exit {result.returncode}): {result.stderr.strip()}")
    return result.stdout