import boto3
from botocore.exceptions import ProfileNotFound
import os, time, pickle, sys, json
from datetime import datetime

CACHE_FILE_EXT = "ec2_instances.cache"
STATE_FILE = 'alfred-aws-state'
MAX_CACHE_AGE = 10    #10s
EXPIRATION_WINDOW = 2 #2s

#Alter the next 2 functions to change what fields are searched and appear in alfred
def parse_title(instance):
  return [
    instance.tags.get('Name', ''),
    instance.tags.get('aws:autoscaling:groupName', ''),
  ]

def parse_subtitle(instance):
  return [
    instance.id,
    str(instance.instance_type),
    getattr(instance, 'private_ip_address', '') or getattr(instance, 'public_ip_address', ''),
    str(instance.state),
  ]

# Alter the next function to change the return value
def pick_result_field(instance, fieldname):
  return {
    'priv': getattr(instance, 'private_ip_address', ''),
    'pub' : getattr(instance, 'ip_address', ''),
    'ami' : getattr(instance, 'image_id', ''),
    'id'  : getattr(instance, 'id', ''),
    ''    : getattr(instance, 'private_ip_address', '')
  }[fieldname]

#-----------------------


def get_instances(profile):
  if not profile: profile = 'default'
  cache_file = profile + '-' + CACHE_FILE_EXT
  if not os.path.isfile(cache_file) or time.time() - os.stat(cache_file).st_mtime > MAX_CACHE_AGE:
    ec2 = boto.connect_ec2(profile_name=profile)
    instances = ec2.get_only_instances()
    pickle.dump(instances, open(cache_file, 'w'), pickle.HIGHEST_PROTOCOL)
  
  return pickle.load(open(cache_file))


def search_for_instances(creds):
  profile, remaining = sys.argv[1].split('<', 1) if '<' in sys.argv[1] else (None, sys.argv[1])
  query, output_field = remaining.rsplit('>', 1) if '>' in remaining else (remaining, '')
  if profile == '':
    profile = None
  query = query.split()

  instances = get_instances(profile)

  for instance in instances:
    match = 0  
    text = ' '.join(parse_title(instance) + parse_subtitle(instance))

    for q in query:
      if q in text:
        match += 1

    if match == len(query):
      fb.add_item(
        title = ', '.join(parse_title(instance)) or '',       #protect against potential None (unserializable)
        subtitle = ', '.join(parse_subtitle(instance)) or '',
        arg = pick_result_field(instance, output_field) or ''
      )

  print fb

def get_valid_creds(profile=None):
  creds = STATE['creds_cache'][profile]
  if creds['expires'] >= datetime.utcfromtimestamp() + EXPIRATION_WINDOW:
    return False
  else:
    return {
      'aws_access_key_id': creds['access_key'],
      'aws_secret_access_key': creds['secret_key'],
      'security_token': creds['session_token'],
    }

# def update_creds(mfa, profile, creds_cache_file):
#   sts = boto.sts.STSConnection(profile_name=profile)
#   creds = sts.get_session_token(
#     duration = 3600,
#     mfa_token = mfa,
#   )

#   with open(creds_cache_file, 'rw') as f:
#     json.dump({
#       'access_key': creds.access_key,
#       'secret_key': creds.secret_key,
#       'session_token': creds.session_token,  
#     }, f)



def prompt_for_mfa(creds_cache_file):
  """
  We cache the temp credentials ourselves
  Boto will cache creds for the lifetime of the script
  and use standard config files for us
  """
  pass


def get_profiles():
  credentials_file = 


if __name__ == '__main__':
  # Switch for JSON format: https://www.alfredapp.com/help/workflows/inputs/script-filter/json/
  # TODO: remove
  # fb = Feedback()
  
  # Various state is stored in this file, e.g. cached temporary credentials &
  # the last-used profile. We load it as a global before main(), and any changes made
  # to it are saved afterwards.
  with open(STATE_FILE, 'r+') as f:
    STATE = json.load(f)
    
    # If the user provided a profile, use and save it
    # If not, try to use the one in STATE
    # If that doesn't work, use default
    try:
      profile = sys.argv[1]
      sesssion = boto3.Session(profile_name=profile)
      STATE['last_profile'] = profile
    except ProfileNotFound:
      profile = STATE.get('last_profile', None)
      session = boto3.Session(profile_name=profile)
    
    creds = get_valid_creds()
    if not creds:
      prompt_for_mfa()
      # the result of the mfa input goes to the next stage in the workflow
    else:
      search_for_instances(creds)
    
    json.dump(STATE, f)


"""
Creds cache file content should look like this:
{
  "my-profile-1": {
    "access_key": "xxxxxxx",
    "secret_key": "xxxxxxx",
    "session_token": "xxxxxxxxx"
  },
  "my-profile-2": {
    "access_key": "xxxxxxx",
    "secret_key": "xxxxxxx",
    "session_token": "xxxxxxxxx"
  }
}
"""

# if script filter -> script filter, the selection in the first becomes search text in the second.
# the script can't read it from stdin.