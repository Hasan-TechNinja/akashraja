# game/utils.py
import asyncio
def fire_and_forget(coro):
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(coro)
    except RuntimeError:
        # Not in an event loop; ignore or log
        pass
