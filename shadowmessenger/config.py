class MessengerConfig:
    def __init__(self, keep_alive_interval = 10, timeout = 30) -> None:
        KEEP_ALIVE_INTERVAL = keep_alive_interval
        TIMEOUT = timeout
        super().__init__()