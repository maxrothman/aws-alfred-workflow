from feedback import Feedback
import boto
import os, time, pickle, sys

CACHE_FILE_EXT = "ec2_instances.cache"
MAX_CACHE_AGE = 10    #10s

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
    'pub' : getattr(instance, 'public_ip_address', ''),
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

def main():
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


if __name__ == '__main__':
  fb = Feedback()
  main()
