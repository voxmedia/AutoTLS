import logging
import sys

from tlstool import settings

LOG_FORMAT = settings.LOG_FORMAT

def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FORMAT,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
