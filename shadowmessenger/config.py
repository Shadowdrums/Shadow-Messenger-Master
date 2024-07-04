class MessengerConfig:
    def __init__(self, keep_alive_interval = 10, timeout = 30) -> None:
        self.KEEP_ALIVE_INTERVAL = keep_alive_interval
        self.TIMEOUT = timeout
        super().__init__()
