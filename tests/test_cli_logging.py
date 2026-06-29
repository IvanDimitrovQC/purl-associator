from __future__ import annotations

import logging
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

from scripts.cli_logging import configure_logging


class CliLoggingTests(unittest.TestCase):
    def test_configure_logging_writes_local_log_file(self) -> None:
        root_logger = logging.getLogger()
        original_handlers = root_logger.handlers[:]
        original_level = root_logger.level
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "demo.log"

            try:
                with redirect_stderr(StringIO()):
                    configured = configure_logging(
                        command_name="demo-command",
                        log_level="INFO",
                        log_file=log_path,
                    )
                    logging.getLogger("tests.demo").info("hello from test")
                    for handler in root_logger.handlers:
                        handler.flush()
            finally:
                for handler in root_logger.handlers[:]:
                    root_logger.removeHandler(handler)
                    handler.close()
                for handler in original_handlers:
                    root_logger.addHandler(handler)
                root_logger.setLevel(original_level)

            text = log_path.read_text()

        self.assertEqual(configured, log_path)
        self.assertIn("logging configured command=demo-command", text)
        self.assertIn("hello from test", text)


if __name__ == "__main__":
    unittest.main()
