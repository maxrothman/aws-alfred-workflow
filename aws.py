"""
A collection of commands used in this workflow
"""

import json, click, sys, time, uuid, os, pickle
from datetime import datetime
from numbers import Number

EXPIRATION_WINDOW = 2   #seconds
CACHE_DIR = 'caches'
CREDS_CACHE_FILE = os.path.join(CACHE_DIR, "creds.cache")
CACHE_FILE_EXT = "aws-instances.cache"
MAX_CACHE_AGE = 40      #seconds

@click.group()
def cli():
  #Make sure cache dir exists
  if not os.path.exists(CACHE_DIR):
    os.mkdir(CACHE_DIR)


@cli.command()
def get_profiles():
  """Print a alfred-formatted list of available boto profiles"""
  from boto3 import Session   #Late import because importing boto3 is slow
  profiles = Session()._session.full_config['profiles'].keys()
  
  result = {
    "items": [
      {
        "uid": profile,
        "title": profile,
        "arg": profile,
        "autocomplete": profile,
      }
      for profile in profiles
    ]
  }

  click.echo(json.dumps(result))


@cli.command()
@click.argument('profile')
def check_profile(profile):
  """
  If no MFA is necessary for "profile", exits with status 2
  If an MFA is neccessary for "profile" but the cached temporary credentials are expired, exit with status 1
  If an MFA is required for "profile" and the cached temporary credentials are still valid, exit with status 0
  """
  from boto3 import Session   #Late import because importing boto3 is slow
  
  config = Session(profile_name=profile)._session.get_scoped_config()
  if 'role_arn' not in config:
    sys.exit(2) #No MFA necessary, go straight to search
  
  creds_cache = get_creds_cache(profile)

  now = time.time()
  if creds_cache is None or creds_cache['expires'] - EXPIRATION_WINDOW <= now:
    sys.exit(1) #Creds are expired, prompt user for MFA

  sys.exit(0) #Creds are still valid, move along


@cli.command()
@click.argument('profile')
@click.argument('token')
def prompt_for_mfa(profile, token):
  """
  Prompt a user for their MFA token, retrieve temporary credentials,
  store them in the cache, then pass them to the next stage
  """
  #TODO; once they begin typing, switch to an invalid "continue" item
  #TODO: if token is wrong, switch to an invalid "invalid token" item
  temp_creds = get_temp_creds(profile, token)
  if temp_creds is None:
    return

  update_creds_cache(profile, temp_creds)
  click.echo(json.dumps({
    "items": [{
        "title": "Continue",
        "arg": "PLACEHOLDER",   #If "arg" is not set, the option will not be selectable
    }]
  }))


@cli.command()
@click.option('--profile')
@click.argument('query')
def search_for_instances(profile, query):
  temp_creds = get_creds_cache(profile)
  query = query.split()
  result = {"items": []}

  instances = get_instances(profile, temp_creds)

  for instance in instances:
    title = instance_title(instance)
    subtitle = instance_subtitle(instance)
    text = title + subtitle
    match = 0

    for q in query:
      if q in text:
        match += 1

    if match == len(query):
      entry = {
        'uid': instance.id,
        'title': title or '',       #Protect against potential None (unserializable)
        'subtitle': subtitle or '',
        'mods': {
          'shift': {
            'arg': json.dumps(extract_output_fields(instance)),
            'subtitle': "More options",
            'valid': True
          }
        }
      }

      # If the instance doesn't have a private IP address, the only valid action is "More options"
      arg = {'arg': instance.private_ip_address} if getattr(instance, 'private_ip_address', False) else {'valid': False}
      entry.update(arg)

      result['items'].append(entry)

  click.echo(json.dumps(result))


@cli.command()
@click.argument('spec')
@click.argument('query')
def filter_output_fields(spec, query):
  """Filters on both title and subtitle, unlike default Alfred filtering, which filters only on title"""
  spec = json.loads(spec)

  results = {
    "items": [
      item for item in spec['items']
      if query in item.get('title', '').lower() or query in item.get('subtitle', '').lower()
    ]
  }

  click.echo(json.dumps(results))


######## Helper functions ########
def get_creds_cache(profile):
  """Return the creds cache for a particular profile"""
  if os.path.exists(CREDS_CACHE_FILE):
    with open(CREDS_CACHE_FILE, 'r') as f:
      return json.load(f)[profile]
  else:
    return None


def update_creds_cache(profile, dct):
  """Update the creds cache with <dct> as its new value"""
  if os.path.exists(CREDS_CACHE_FILE):
    with open(CREDS_CACHE_FILE, 'r') as f:
      creds = json.load(f)
    creds[profile] = dct
    new_creds = creds
  else:
    new_creds = {profile: dct}

  with open(CREDS_CACHE_FILE, 'w') as f:
    json.dump(new_creds, f)


def get_temp_creds(profile, token):
  """Use STS to retrieve temporary credentials for <profile>"""
  if len(token) != 6:
    return None

  from boto3 import Session   #Late import because importing boto3 is slow
  session = Session(profile_name=profile)
  config = session._session.get_scoped_config()

  hub_client = Session(profile_name=config['source_profile']).client('sts')

  response = hub_client.assume_role(
    RoleArn = config['role_arn'],
    RoleSessionName = 'alfed-aws-{}@{}'.format(str(uuid.uuid4())[:8], profile),
    DurationSeconds = 3600,
    SerialNumber = config['mfa_serial'],
    TokenCode = token,
  )

  temp_creds = response['Credentials']

  return {
    'access_key': temp_creds['AccessKeyId'],
    'secret_key': temp_creds['SecretAccessKey'],
    'session_token': temp_creds['SessionToken'],
    #Python's datetime lib is dumb and doesn't know how to turn timezone-aware datetimes
    #into epoch timestamps. Since the datetime boto returns and the datetime returned
    #by datetime.utcfromtimestamp() are both in UTC, this is safe.
    'expires': (temp_creds['Expiration'].replace(tzinfo=None) - datetime.utcfromtimestamp(0)).total_seconds(),
  }


def get_instances(profile, temp_creds):
  """Get a list of all instances in the account from AWS"""
  # import pdb; pdb.set_trace()
  cache_file = os.path.join(CACHE_DIR, profile + '-' + CACHE_FILE_EXT)
  if temp_creds is not None:
    cred_kwargs = {
      'aws_access_key_id': temp_creds['access_key'],
      'aws_secret_access_key': temp_creds['secret_key'],
      'aws_session_token': temp_creds['session_token'],
    }
  else:
    cred_kwargs = {}

  if not os.path.isfile(cache_file) or os.stat(cache_file).st_mtime + MAX_CACHE_AGE < time.time():
    from boto3 import Session  #Late import because importing boto3 is slow

    ec2 = Session(profile_name=profile, **cred_kwargs).resource('ec2')
    instances = map(SerializableInstance, ec2.instances.all())

    with open(cache_file, 'w') as f:
      pickle.dump(instances, f, pickle.HIGHEST_PROTOCOL)

    return instances
  
  with open(cache_file) as f:
    return pickle.load(f)


def instance_title(instance):
  tags = {t['Key']: t['Value'] for t in instance.tags} if getattr(instance, 'tags', None) else {}
  return ' '.join([
    tags.get('Name', ''),
    tags.get('aws:autoscaling:groupName', ''),
  ])


def instance_subtitle(instance):
  return ' '.join([
    instance.id,
    instance.instance_type,
    getattr(instance, 'private_ip_address', None) or getattr(instance, 'public_ip_address', None) or '',
    instance.state['Name'],
  ])


def extract_output_fields(instance):
  output_fields = [
    {'prop': 'id',                 'desc': 'Instance ID'},
    {'prop': 'image_id',           'desc': 'AMI ID'},
    {'prop': 'instance_type',      'desc': 'Type'},
    {'prop': 'private_dns_name',   'desc': 'Private Hostname'},
    {'prop': 'private_ip_address', 'desc': 'Private IP Address'},
    {'prop': 'public_dns_name',    'desc': 'Public Hostname'},
    {'prop': 'public_ip_address',  'desc': 'Public IP Address'},
    {'prop': 'subnet_id',          'desc': 'Subnet ID'},
    {'prop': 'vpc_id',             'desc': 'VPC ID'},
  ]

  return {
    'items': [
      {
        'uid': field['prop'],
        'title': getattr(instance, field['prop']),
        'subtitle': field['desc'],
        'arg': getattr(instance, field['prop']),
      }
      for field in output_fields if getattr(instance, field['prop'], None)
    ]
  }


class SerializableInstance(object):
  """A wrapper for Boto3 Instance resources that is pickleable"""
  def __init__(self, instance):
    for prop in dir(instance):
      val = getattr(instance, prop)
      if self._is_serializable(val):
        setattr(self, prop, val)


  def _is_serializable(self, val):
    if isinstance(val, Number):
      return True
    elif isinstance(val, str):
      return not val.startswith('__')
    elif isinstance(val, dict):
      return all(self._is_serializable(v) for v in val.values())
    elif isinstance(val, list):
      return all(self._is_serializable(i) for i in val)
    return False



if __name__ == '__main__':
  cli()
