import dotenv
import logging
import os
import pymisp
import requests

from _version import __version__


dotenv.load_dotenv()

API_KEY = os.getenv('GTI_APIKEY')
LIMIT = int(os.getenv('LIMIT', 10))
MISP_URL = os.getenv('MISP_URL')
MISP_API_KEY = os.getenv('MISP_APIKEY')
MISP_SSL = os.getenv('MISP_SSL', 'false').lower() in ('true', '1', 't')
DC_URL = 'https://www.virustotal.com/api/v3/data_connector_configs?relationships=data_connector'
MISP_THREAT_INTEL_URL = 'https://www.virustotal.com/api/v3/misp_threat_intel/{dcc_id}'

HEADERS = {
    'x-apikey': API_KEY,
    'x-tool': f'MispConnector_{__version__}', 
    'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImE1NzMzYmJiZDgxOGFhNWRiMTk1MTk5Y2Q1NjhlNWQ2ODUxMzJkM2YiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiIyMzQ2NzI1MjIyNDgtaWY3Mmk3ODhnY29xOXN0OXRscHRnNHE3ZjJlMzhuam8uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhenAiOiIxMDcxMzI3NjU4MTkyMjI5NzY5MDciLCJlbWFpbCI6ImFwaS1jYWxsZXJAdmlydXN0b3RhbGNsb3VkLXN0YWdpbmcuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZXhwIjoxNzYzOTk5NTgyLCJpYXQiOjE3NjM5OTU5ODIsImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbSIsInN1YiI6IjEwNzEzMjc2NTgxOTIyMjk3NjkwNyJ9.y997fPhrvWJYPsQAczCoq6usJkbD61JqqiuU9Rm_Mlwfu5Iy6dax3Z0cBaIrROzuhq4cz9F7km5qypAeNR79THWkQrR6wk5SljFgtVSFXKDdlqXKezwYz6NvaJ8YqgNYpQE0kTnACyupkZSK8Qpdg6Gb7W2E7Dvb1w3N3PP_dY1tmftgKn6mAxLToGJJA0zPdNceRhZukTrv37cvsujZ17eMliA80mEqj1J-pnS6sNZjqf5MkZXagsEdRdHB2vcb0WqcwEKEpDx2BCmpX-fyizY_gMqkU_hMJiUaUv4YhqtXW-oY8A5rmdbT0MCKiIS7_Eq8im1zr1zRz98r9ranOw',
}


def get_dcc_id() -> str:
  response = requests.get(DC_URL, headers=HEADERS, timeout=30)
  response.raise_for_status()
  data = response.json()['data']
  for dcc in data:
    if dcc.get('relationships', {}).get('data_connector', {}).get('data', {}).get('id') == '22019996788':
      dcc_id = dcc['id']
      if dcc.get('attributes', {}).get('config', {}).get('MISP_URL'):
        raise ValueError('MISP DC "%s" is PUSH. Please switch to PULL.', dcc_id)
      logging.info('MISP DC: %s', dcc_id)
      return dcc_id
  raise ValueError('MISP DC not found.')


def get_messages(dcc_id: str) -> list[dict[str, str]]:
  logging.info('Getting messages from VT...')
  response = requests.get(
      MISP_THREAT_INTEL_URL.format(dcc_id=dcc_id),
      params={'limit': LIMIT},
      headers=HEADERS,
      timeout=300,
  )
  response.raise_for_status()
  return response.json()['data']


def _create_misp_event(event: str):
  misp_event = pymisp.MISPEvent()
  misp_event.from_json(event)
  return misp_event


def _create_misp_attribute(attribute: str):
  misp_attribute = pymisp.MISPAttribute()
  misp_attribute.from_json(attribute)
  return misp_attribute


def send_to_misp(session: pymisp.PyMISP, message: dict[str, str | list[str]]) -> dict:
  misp_event = _create_misp_event(message['event'])
  attributes = message.get('attributes')
  if attributes is not None:
    logging.info('Adding %s attributes to %s (%s)', len(attributes), misp_event.uuid, misp_event.info)
    misp_attributes = []
    for attribute in attributes:
      misp_attribute = _create_misp_attribute(attribute)
      misp_attributes.append(misp_attribute)
    if misp_attributes:
      logging.info('Checking event %s (%s)', misp_event.uuid, misp_event.info)
      if not session.event_exists(misp_event.uuid):
        logging.info('Creating event %s (%s)', misp_event.uuid, misp_event.info)
        session.add_event(misp_event)
      logging.info('Adding %s attributes to %s (%s)', len(attributes), misp_event.uuid, misp_event.info)
      return session.add_attribute(misp_event.uuid, misp_attributes, break_on_duplicate=False)
  else:
    logging.info('Checking event %s (%s)', misp_event.uuid, misp_event.info)
    if session.event_exists(misp_event.uuid):
      logging.info('Creating event %s (%s)', misp_event.uuid, misp_event.info)
      return session.update_event(misp_event)
    logging.info('Updating event %s (%s)', misp_event.uuid, misp_event.info)
    return session.add_event(misp_event)


def process_misp_response(misp_response: dict):
  short_response = {}

  if 'Event' in misp_response:
    short_response.update(
        {
            'Event': {
                key: misp_response['Event'][key]
                for key in ('uuid', 'info')
            }
        }
    )
  if 'Attribute' in misp_response:
    if isinstance(misp_response['Attribute'], list):
      short_response.update(
          {
              'Attribute': [
                  {
                      key: attribute[key] for key in ('type', 'value')
                  }
                  for attribute in misp_response['Attribute']
              ]
          }
      )
    else:
      short_response.update(
          {
              'Attribute': {
                  key: misp_response['Attribute'][key]
                  for key in ('type', 'value')
              }
          }
      )
  error_code, msg = misp_response.get('errors', (None, None))
  if error_code:
    short_response.update({'Error': {'code': error_code, 'message': msg}})

  return short_response


def fetch_data():
  """Fetches data from the endpoint using the API key."""
  if not API_KEY:
    raise ValueError('Error: GET_APIKEY must be set in the environment or .env file.')

  dcc_id = get_dcc_id()
  session = pymisp.PyMISP(MISP_URL, MISP_API_KEY, ssl=MISP_SSL)

  sent_messages = 0
  i = 0
  while (messages := get_messages(dcc_id)):
    logging.info('Length from VT: %s', len(messages))
    misp_responses = []
    for message in messages:
      misp_response = send_to_misp(session, message)
      if misp_response:
        misp_responses.append(process_misp_response(misp_response))
    i += 1
    logging.info('Length to MISP: %s', len(misp_responses))
    sent_messages += len(misp_responses)
    logging.info('Total length to MISP: %s', sent_messages)

  return sent_messages


if __name__ == '__main__':
  logging.info('Fetching data once...')
  data = fetch_data()
  logging.info('Messages to MISP: %s', data)
