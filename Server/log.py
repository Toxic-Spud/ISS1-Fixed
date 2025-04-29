import logging


logging.basicConfig(format='%(asctime)s %(message)s')


class CustomLogger:
    def __init__(self, name, level):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(level)
        self._logger.propagate = False
        handler = logging.FileHandler(f"{name}.log")
        formatter = logging.Formatter('%(asctime)s %(message)s')
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)

    def info(self, message):
        self._logger.info(message)
    
    def warn(self, message):
        self._logger.warning(message)



ALERT_LOGGER = CustomLogger("Security_Alert", logging.WARNING)


INFO_LOGGER = CustomLogger("Info", logging.INFO)
