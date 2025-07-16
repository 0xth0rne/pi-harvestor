import logging
import os
from datetime import datetime 

def setup_logger():
    # Make the /log directory, create a log based off the time
    os.makedirs("logs", exist_ok=True)
    log_filename = f"logs/{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"

    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(levelname)s] %(asctime)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )