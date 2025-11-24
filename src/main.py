import argparse
import logging
import requests
import sys

import api_client
import scheduler

from _version import __version__


RELEASES_URL = 'https://api.github.com/repos/VirusTotal/gti-misp-connector/releases/latest'


def check_for_updates():
  """Checks for new releases on GitHub by simple string comparison."""
  try:
    response = requests.get(RELEASES_URL)
    latest_release = response.json().get('name')

    if latest_release != __version__:
      logging.warning('------ UPDATE AVAILABLE ------')
      logging.warning('Warning: You are using version %s, but version %s is available.', __version__, latest_release)
      logging.warning('Please consider updating: %s', RELEASES_URL)
      logging.warning('------------------------------')

  except requests.exceptions.RequestException as e:
    logging.error('Could not check for updates: %s', str(e))
  except Exception as e:
    logging.error('Error while checking for updates: %s', str(e))


def main():
  logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stdout)
  parser = argparse.ArgumentParser(description='MISP Connector')
  parser.add_argument('--once', action='store_true', help='Run the data fetch job once.')
  parser.add_argument('--schedule', type=int, help='Run the data fetch job periodically every N seconds.')

  args = parser.parse_args()

  check_for_updates()

  if args.once:
    logging.info('Running job once...')
    data = api_client.fetch_data()
    logging.info('Messages to MISP: %s', data)
  elif args.schedule:
    if args.schedule <= 0:
      logging.error('Error: --schedule interval must be a positive integer.')
      return
    scheduler.run_scheduler(args.schedule)
  else:
    logging.info('Please specify a run mode: --once or --schedule <seconds>')
    parser.print_help()


if __name__ == '__main__':
  main()
