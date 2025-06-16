# app/core/logging_config.py
import logging
import sys
from pythonjsonlogger import jsonlogger
from app.core.config import settings

class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        if not log_record.get('timestamp'):
            log_record['timestamp'] = record.created
        if record.levelno: # Ensure level is always present
            log_record['level'] = record.levelname
        else:
            log_record['level'] = logging.getLevelName(record.levelno) # Fallback
        if record.name:
            log_record['logger_name'] = record.name
        # Add more custom fields if needed

def setup_logging():
    log_level = logging.DEBUG if settings.DEBUG else logging.INFO
    
    # Remove any existing handlers from the root logger
    # This is important if Uvicorn/Gunicorn add their own default handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # Configure the root logger
    logger = logging.getLogger() # Get root logger
    logger.setLevel(log_level)

    # Add a stream handler with JSON formatter
    log_handler = logging.StreamHandler(sys.stdout) # Log to stdout
    formatter = CustomJsonFormatter('%(timestamp)s %(level)s %(name)s %(message)s')
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)

    # Configure Uvicorn access logs to use JSON if possible (or disable and log requests in middleware)
    # This can be tricky as Uvicorn/Gunicorn have their own logger instances.
    # Often, it's easier to disable their default access logger and log requests via middleware.
    logging.getLogger("uvicorn.access").handlers = [log_handler] if settings.DEBUG else []
    logging.getLogger("uvicorn.access").propagate = settings.DEBUG # Propagate in debug, disable in prod to avoid double logs if handled by middleware

    logging.getLogger("gunicorn.error").handlers = [log_handler]
    logging.getLogger("gunicorn.access").handlers = [log_handler] if settings.DEBUG else []
    logging.getLogger("gunicorn.access").propagate = settings.DEBUG


    print(f"Structured JSON logging configured at level: {logging.getLevelName(log_level)}")

    # Example log to test
    # logging.info("Test log message from setup_logging.", extra={"test_field": "test_value"})
    