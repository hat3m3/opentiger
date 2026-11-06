"""Live terminal feedback without contaminating redirected or JSON output."""
import sys
import threading
import time

from . import terminal as ui


class Progress:
    def __init__(self, label, enabled=True):
        self.label = label
        self.enabled = enabled
        self.started = time.perf_counter()
        self.state = (0, 1, label)
        self.stop = threading.Event()
        self.thread = None

    def __enter__(self):
        if self.enabled and ui.supports_color():
            self.thread = threading.Thread(target=self.animate, daemon=True)
            self.thread.start()
        return self

    def __call__(self, completed, total, label):
        self.state = (completed, total, str(label))
        if self.enabled and self.thread is None:
            print(ui.message(f'[{completed}/{total}] {label}'), flush=True)

    def animate(self):
        index = 0
        while not self.stop.wait(0.12):
            done, total, label = self.state
            elapsed = time.perf_counter() - self.started
            label = str(label).replace('\x1b', '')[:max(10, ui.width() - 35)]
            sys.stdout.write('\r\033[2K  ' + ui.ink('|/-\\'[index % 4], 'accent') + f' [{done}/{total}] {label}  {elapsed:.1f}s')
            sys.stdout.flush()
            index += 1

    def __exit__(self, *args):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=1)
            sys.stdout.write('\r\033[2K')
            sys.stdout.flush()
