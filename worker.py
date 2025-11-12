# worker.py
import os
from redis import Redis
from rq import Queue, Worker

# Queue name must match what API enqueues
QUEUE_NAME = os.getenv("RQ_QUEUE", "deepchecks")

def main():
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    r = Redis.from_url(redis_url)
    worker = Worker([QUEUE_NAME], connection=r)
    print(f"Worker listening on queue '{QUEUE_NAME}' with {redis_url}")
    worker.work(with_scheduler=True)

if __name__ == "__main__":
    main()
