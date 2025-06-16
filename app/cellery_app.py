# app/celery_app.py
from celery import Celery
from app.core.config import settings

# Note: Celery's interaction with async/await in FastAPI tasks can be tricky.
# For tasks that need to run DB operations with SQLAlchemy async,
# you'll need a way to run the async code within the synchronous Celery worker.
# asyncio.run() can be used inside tasks, or specialized libraries/patterns.

# Ensure CELERY_ENABLED is checked before trying to use Celery features.
if settings.CELERY_ENABLED:
    celery_app = Celery(
        "osp_worker", # Name of the celery application
        broker=settings.CELERY_BROKER_URL,
        backend=settings.CELERY_RESULT_BACKEND,
        include=['app.tasks'] # List of modules to import when the worker starts
                              # This is where our task functions will live.
    )

    # Optional Celery configuration using settings from config.py
    celery_app.conf.update(
        task_serializer='json',
        accept_content=['json'],  # Ensure tasks accept json
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        worker_prefetch_multiplier=1, # Important for long-running tasks
        task_acks_late=True,          # Ensure tasks are acknowledged after completion
        # task_default_queue=settings.CELERY_TASK_DEFAULT_QUEUE, # Set default queue
        # task_routes=settings.CELERY_TASK_ROUTES, # Define task routing
    )

    # Example: If you want to define default queue and routes here if not complex
    if hasattr(settings, 'CELERY_TASK_DEFAULT_QUEUE'):
         celery_app.conf.task_default_queue = settings.CELERY_TASK_DEFAULT_QUEUE
    if hasattr(settings, 'CELERY_TASK_ROUTES') and settings.CELERY_TASK_ROUTES:
         celery_app.conf.task_routes = settings.CELERY_TASK_ROUTES


    # A simple health check task for Celery itself (optional)
    @celery_app.task(name="celery.health_check")
    def health_check():
        return "Celery is healthy!"

else:
    # If Celery is not enabled, create a placeholder celery_app or handle calls gracefully.
    # This allows other modules to import `celery_app` without error.
    # Calls to celery_app.send_task will need to be conditional.
    print("[Celery] Celery is DISABLED via settings.CELERY_ENABLED=False. Tasks will not be queued.")
    
    class DummyCeleryApp:
        def task(self, *args, **kwargs):
            def decorator(func):
                def wrapper(*args_wrapper, **kwargs_wrapper):
                    print(f"[DummyCeleryTask] Task '{func.__name__}' called but Celery is disabled. Args: {args_wrapper}, Kwargs: {kwargs_wrapper}")
                    # Simulate immediate execution or just log
                    # For a real dummy, it might execute the function synchronously if desired,
                    # or return a dummy TaskAsyncResult.
                    # For now, just print.
                    # return func(*args_wrapper, **kwargs_wrapper) # If you want to run it sync
                    return None 
                return wrapper
            return decorator

        def send_task(self, name, args=None, kwargs=None, **options):
            print(f"[DummyCeleryApp] send_task '{name}' called but Celery is disabled. Args: {args}, Kwargs: {kwargs}")
            return None # Or a dummy result object

    celery_app = DummyCeleryApp()

# You might need a way to run async database operations from within synchronous Celery tasks.
# This is a common challenge. Here's a basic helper.
# In a real app, you might use libraries like 'celery-sqlalchemy-async'.
import asyncio
from app.database import AsyncSessionLocal # Import your session factory

async def _run_async_db_task(async_func, *args, **kwargs):
    """Helper to run an async function (that uses DB session) from a sync Celery task."""
    async with AsyncSessionLocal() as session:
        try:
            result = await async_func(session, *args, **kwargs)
            await session.commit()
            return result
        except Exception as e:
            await session.rollback()
            # Log the exception properly here
            print(f"Error in async DB task: {e}")
            raise # Re-raise to let Celery handle task failure

def run_async_in_celery_task(async_func):
    """Decorator or helper to simplify running async DB logic in Celery tasks."""
    def wrapper(*args, **kwargs):
        # This runs the async_func within a new event loop for the Celery task
        return asyncio.run(_run_async_db_task(async_func, *args, **kwargs))
    return wrapper