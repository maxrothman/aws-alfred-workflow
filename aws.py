"""
A collection of commands used in this workflow
"""

import json, click, sys, time, uuid, os, pickle
from datetime import datetime
from numbers import Number
from botocore.exceptions import ClientError

EXPIRATION_WINDOW = 2    #seconds
CACHE_DIR = 'caches'
CREDS_CACHE_FILE = os.path.join(CACHE_DIR, "creds.cache")
CONFIG_CACHE_FILE = os.path.join(CACHE_DIR, "boto-config.cache")
INSTANCES_CACHE_EXT = "aws-instances.cache"
INSTANCES_CACHE_MAX_AGE = 40    #seconds

@click.group()
def cli():
  """Main group for other subcommands"""
  #Make sure cache dir exists
  if not os.path.exists(CACHE_DIR):
    os.mkdir(CACHE_DIR)

#--------------------------------------------------------

@cli.command()
def get_profiles():
  """Print a alfred-formatted list of available boto profiles"""
  profiles = get_boto_config().keys()
  
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

#--------------------------------------------------------

@cli.command()
@click.argument('profile')
def check_profile(profile):
  """
  If no MFA is necessary for <profile>, exits with status 2
  If an MFA is neccessary for <profile> but the cached temporary credentials are expired, exit with status 1
  If an MFA is required for <profile> and the cached temporary credentials are still valid, exit with status 0
  """
  config = get_boto_config([profile])

  if 'role_arn' not in config:
    sys.exit(2) #No MFA necessary, go straight to search
  
  creds_cache = get_creds_cache(profile)

  now = time.time()
  if creds_cache is None or creds_cache['expires'] - EXPIRATION_WINDOW <= now:
    sys.exit(1) #Creds are expired, prompt user for MFA

  sys.exit(0) #Creds are still valid, move along

#--------------------------------------------------------

@cli.command()
@click.argument('profile')
@click.argument('token')
def prompt_for_mfa(profile, token):
  """
  Prompt a user for their MFA token, retrieve temporary credentials,
  store them in the cache, then pass them to the next stage
  """
  if len(token) < 6:
    click.echo(json.dumps({'items': [{'title': '...', 'valid': False}]}))
  elif len(token) > 6:
    click.echo(json.dumps({'items': [{'title': 'Token too long!', 'valid': False}]}))
  else:
    try:
      temp_creds = get_temp_creds(profile, token)
    except ClientError:
      click.echo(json.dumps({'items': [{'title': 'Invalid token!', 'valid': False}]}))
    except:
      click.echo(json.dumps({'items': [{'title': 'Unexpected error!', 'valid': False}]}))
    else:
      update_creds_cache(profile, temp_creds)
      click.echo(json.dumps({
        "items": [{
            "title": "Continue",
            "arg": "PLACEHOLDER",   #If "arg" is not set, the option will not be selectable
        }]
      }))


def get_temp_creds(profile, token):
  """Use STS to retrieve temporary credentials for <profile>"""
  from boto3 import Session   #Late import because importing boto3 is slow

  config = get_boto_config()[profile]
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

#--------------------------------------------------------

@cli.command()
@click.option('--profile')
@click.argument('query')
def search_for_instances(profile, query):
  """
  Print an alfred-formatted list of instances in the AWS account given by <profile> that match <query>
  """
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
            #Pass the selected result as a string to the next node, which filters it
            'arg': json.dumps(extract_output_fields(instance)),
            'subtitle': "More options",
            'valid': True
          }
        }
      }

      # If the instance doesn't have a private IP address, the only valid action is "More options"
      arg = ({'arg': instance.private_ip_address} 
        if getattr(instance, 'private_ip_address', False) 
        else {'valid': False})
      entry.update(arg)

      result['items'].append(entry)

  click.echo(json.dumps(result))


def get_instances(profile, temp_creds):
  """Get a list of all instances in the account given by <profile> from AWS"""

  cache_file = os.path.join(CACHE_DIR, profile + '-' + INSTANCES_CACHE_EXT)

  if temp_creds is not None:
    cred_kwargs = {
      'aws_access_key_id': temp_creds['access_key'],
      'aws_secret_access_key': temp_creds['secret_key'],
      'aws_session_token': temp_creds['session_token'],
    }
  else:
    cred_kwargs = {}

  if not os.path.isfile(cache_file) or os.stat(cache_file).st_mtime + INSTANCES_CACHE_MAX_AGE < time.time():
    from boto3 import Session  #Late import because importing boto3 is slow

    ec2 = Session(profile_name=profile, **cred_kwargs).resource('ec2')
    instances = map(SerializableInstance, ec2.instances.all())

    with open(cache_file, 'w') as f:
      pickle.dump(instances, f, pickle.HIGHEST_PROTOCOL)

    return instances

  else:
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

#--------------------------------------------------------

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


######## Shared helper functions ########
def get_creds_cache(profile):
  """Return the creds cache for a particular profile"""
  if os.path.exists(CREDS_CACHE_FILE):
    with open(CREDS_CACHE_FILE, 'r') as f:
      return json.load(f)[profile]
  else:
    return None


def get_boto_config():
  """Return full boto config. Caches responses for performance."""
  cf_files = filter(os.path.exists, map(os.path.expanduser,
    ['~/.aws/config', '~/.aws/credentials', '/etc/boto.cfg', '~/.boto']))
  env_vars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
    'AWS_DEFAULT_REGION', 'AWS_PROFILE', 'AWS_CONFIG_FILE', 'AWS_SHARED_CREDENTIALS_FILE',
    'AWS_CA_BUNDLE', 'AWS_METADATA_SERVICE_TIMEOUT', 'AWS_METADATA_SERVICE_NUM_ATTEMPTS',
    'AWS_DATA_PATH']

  if os.path.exists(CONFIG_CACHE_FILE):
    with open(CONFIG_CACHE_FILE) as f:
      cache = json.load(f)

    cache_invalid = (
      any(os.stat(cf).st_mtime > os.stat(CONFIG_CACHE_FILE).st_mtime for cf in cf_files) or
      any(os.environ.get(cv) != cache['env'].get(cv) for cv in env_vars)
    )
  else:
    cache_invalid = True

  if cache_invalid:
    from boto3 import Session   #late import because importing boto3 is slow
    config = Session()._session.full_config['profiles']
    with open(CONFIG_CACHE_FILE, 'w') as f:
      json.dump({'config': config, 'env': {cv: os.environ.get(cv) for cv in env_vars}}, f)
    return config

  else:
    return cache['config']


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
    else:
      return False



if __name__ == '__main__':
  cli()

#TODO:
# - hooks to jump to any stage in the pipeline
# - parameterize details (e.g. title/subtitle fields)
# - performance
# - add fuzzy matching
