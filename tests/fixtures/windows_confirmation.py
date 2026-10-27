"""Exercise real console input in a hidden, isolated Windows console."""

import ctypes
from ctypes import wintypes
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def console_regression(binary):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GenerateConsoleCtrlEvent.argtypes = [wintypes.DWORD, wintypes.DWORD]

    class Coord(ctypes.Structure):
        _fields_ = [("x", ctypes.c_short), ("y", ctypes.c_short)]

    class Key(ctypes.Structure):
        _fields_ = [("down", wintypes.BOOL), ("repeat", wintypes.WORD),
                    ("virtual_key", wintypes.WORD), ("scan", wintypes.WORD),
                    ("character", wintypes.WCHAR), ("control", wintypes.DWORD)]

    class Event(ctypes.Union):
        _fields_ = [("key", Key), ("padding", ctypes.c_byte * 16)]

    class Record(ctypes.Structure):
        _fields_ = [("kind", wintypes.WORD), ("event", Event)]

    assert ctypes.sizeof(Record) == 20
    kernel.WriteConsoleInputW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Record),
                                          wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.ReadConsoleOutputCharacterW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR,
                                                   wintypes.DWORD, Coord,
                                                   ctypes.POINTER(wintypes.DWORD)]

    def checked(result):
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())
        return result

    def open_console(name):
        handle = kernel.CreateFileW(name, 0xC0000000, 3, None, 3, 0, None)
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    input_handle = open_console("CONIN$")
    output_handle = open_console("CONOUT$")

    def mode():
        value = wintypes.DWORD()
        checked(kernel.GetConsoleMode(input_handle, ctypes.byref(value)))
        return value.value

    def screen():
        text = ctypes.create_unicode_buffer(16384)
        count = wintypes.DWORD()
        checked(kernel.ReadConsoleOutputCharacterW(output_handle, text, len(text),
                                                   Coord(0, 0), ctypes.byref(count)))
        return text[:count.value]

    def wait_for(predicate, label):
        deadline = time.monotonic() + 10
        while not predicate():
            if time.monotonic() >= deadline:
                raise AssertionError(f"timed out waiting for {label}; mode={mode()}")
            time.sleep(0.01)

    def type_reply(reply):
        records = []
        for character in reply:
            virtual_key = 13 if character == "\r" else ord(character.upper())
            for down in (True, False):
                records.append(Record(1, Event(key=Key(down, 1, virtual_key, 0, character, 0))))
        array = (Record * len(records))(*records)
        count = wintypes.DWORD()
        checked(kernel.WriteConsoleInputW(input_handle, array, len(array), ctypes.byref(count)))
        assert count.value == len(array)

    original = mode()
    # Catch Ctrl+C only in this supervisor. Native children keep their default handler.
    signal.signal(signal.SIGINT, lambda *_: None)
    children = []

    def stop_children():
        for child in children:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

    try:
        with tempfile.TemporaryDirectory(prefix="sshw-console-") as directory, ExitStack() as cleanup:
            cleanup.callback(stop_children)
            home = Path(directory)
            config = home / "servers.json"
            config.write_text(json.dumps({
                "version": 2, "default": "probe", "credential_backend": "session_only",
                "servers": {"probe": {"host": "127.0.0.1", "port": 10022,
                    "default_user": "tester", "accounts": {"tester": {"auth": {"type": "agent"}}}}}
            }), encoding="utf-8")
            snapshot = config.read_bytes()
            environment = {key: value for key, value in os.environ.items()
                           if not key.upper().startswith("SSHW_")}
            args = [binary, "--home", str(home), "add", "probe", "--host", "127.0.0.1",
                    "--port", "10022", "--user", "tester"]

            def start(options):
                # stdin must be an actual console even though the supervisor's logs are piped.
                with open("CONIN$", "rb", buffering=0) as terminal:
                    child = subprocess.Popen([*args, *options], stdin=terminal,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             env=environment)
                children.append(child)
                return child

            password = start(["--force"])
            wait_for(lambda: mode() == 1, "password raw mode")
            checked(kernel.GenerateConsoleCtrlEvent(0, 0))
            password.communicate(timeout=10)
            assert password.returncode == 0xC000013A, password.returncode
            assert mode() == 1, "the interrupted password must leave the reproduced raw mode"

            for inherited, reply, expected in [(1, "n\r", 3), (1, "y\r", 0),
                                                (1, "\r", 3), (0x209, "n\r", 3)]:
                checked(kernel.SetConsoleMode(input_handle, inherited))
                prompts = screen().count("[y/N]")
                confirmation = start(["--auth", "agent"])
                wait_for(lambda: screen().count("[y/N]") > prompts, "confirmation prompt")
                active_mode = mode()
                type_reply(reply)
                try:
                    stdout, stderr = confirmation.communicate(timeout=5)
                except subprocess.TimeoutExpired as error:
                    raise AssertionError(f"confirmation did not accept Enter; mode={active_mode}") from error
                assert confirmation.returncode == expected, (stdout, stderr)
                assert active_mode & 7 == 7, f"line, echo and processed input missing: {active_mode}"
                assert active_mode & 0x200 == 0, "confirmation must use cooked rather than VT input"
                assert mode() == inherited, "the prompt must restore the inherited input mode"
                assert config.read_bytes() == snapshot, "decline/no-op changed the configuration"

            # An affirmative confirmation must hand off to hidden password input normally.
            checked(kernel.SetConsoleMode(input_handle, 1))
            prompts = screen().count("[y/N]")
            passwords = screen().count("SSH password:")
            registration = start([])
            wait_for(lambda: screen().count("[y/N]") > prompts, "password registration confirmation")
            type_reply("y\r")
            wait_for(lambda: screen().count("SSH password:") > passwords and mode() == 1,
                     "hidden password input after confirmation")
            secret = "consoleonlyfixture"
            type_reply(secret + "\r")
            stdout, stderr = registration.communicate(timeout=5)
            assert registration.returncode == 0, (stdout, stderr)
            assert secret not in screen()
            assert secret.encode() not in stdout + stderr + config.read_bytes()
            assert mode() == 1
            print("Ctrl+C -> confirmation n/y/empty/VT and hidden password: PASS; original mode restored")
    finally:
        checked(kernel.SetConsoleMode(input_handle, original))
        checked(kernel.CloseHandle(output_handle))
        checked(kernel.CloseHandle(input_handle))


if __name__ == "__main__":
    if sys.argv[1] == "--worker":
        console_regression(sys.argv[2])
    else:
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0  # SW_HIDE: no visible console or UI interaction.
        result = subprocess.run([sys.executable, "-X", "utf8", __file__, "--worker", sys.argv[1]],
                                startupinfo=startup, creationflags=subprocess.CREATE_NEW_CONSOLE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        print(result.stdout.decode("utf-8", errors="replace"), end="")
        sys.exit(result.returncode)
