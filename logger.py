import datetime

NONE = "UNKNOWN"
INFO = "INFO"
WARN = "WARNING"
ERR = "ERROR"
CRIT = "CRITICAL"


class LogError(Exception):
    def __init__(self, msg: str):
        message = f"something went wrong during logging: {msg}"
        super().__init__(message)


class Logger:
    def __init__(self, file_location, log_origin):
        self.path = file_location
        self.origin = log_origin
        self.print_console = False
        self.buffer = []
        self.write(f"logger is online", INFO)

    def write(self, message: str, severity: str = NONE):
        if self.buffer:
            raise LogError("there are still log messages in the buffer,"
                           "please call write_buffer before writing another log message")
        tm = datetime.datetime.now()
        tab = " " * max(0, 35 - len(severity) - len(self.origin))
        msg = f"[{tm}] {severity} from {self.origin}: {tab}{message.upper() if severity in [ERR, CRIT] else message}"

        if self.print_console:
            print(msg)
        try:
            with open(self.path, "a") as f:
                f.write(msg + '\n')
        except OSError as e:
            raise LogError(f"this computer could not open the log file at location: '{self.path}'. "
                           f"OS returned this error: {e.__repr__()}")
        except Exception as e:
            raise LogError(f"unknown error while writing to log file: {e.repr}")

    def write_buffer(self):
        if self.print_console:
            print(msg for msg in self.buffer)
        try:
            with open(self.path, "a") as f:
                for msg in self.buffer: f.write(msg + '\n')
            self.buffer = []
        except OSError as e:
            LogError(f"this computer could not open the log file at location:\n {self.path} \n"
                           f"OS returned this error: {e}")
        except Exception as e:
            raise LogError(f"unknown error while writing to log file: {e}")

    def add(self, message: str, severity: str = NONE):
        tm = datetime.datetime.now()
        tab = " " * max(0, 30 - len(severity) - len(self.origin))
        msg = f"[{tm}] {severity} from {self.origin}: {tab}{message.upper() if severity in [ERR, CRIT] else message}"
        self.buffer.append(msg)

    def set_printing(self, b: bool):
        self.print_console = b
