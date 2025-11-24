import logging
import time

import api_client


def job():
  logging.info('Running scheduled job...')
  data = api_client.fetch_data()
  logging.info('Messages to MISP: %s', data)


def run_scheduler(interval_seconds):
  """Runs the fetch_data job every interval_seconds."""
  logging.info('Scheduling job to run every %s seconds.', interval_seconds)

  while True:
    job()
    time.sleep(interval_seconds)
