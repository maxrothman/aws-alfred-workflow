from feedback import Feedback
import boto
import os, time, pickle, sys

CACHE_FILE = "ec2_instances.cache"
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
    getattr(instance, 'private_ip_address', None) or getattr(instance, 'public_ip_address', None) or '',
    str(instance.state),
  ]

# Alter the next function to change the return value
def pick_result_field(instance):
  return getattr(instance, 'private_ip_address', None) or getattr(instance, 'public_ip_address', None) or ''

#-----------------------


def get_instances():
  if not os.path.isfile(CACHE_FILE) or time.time() - os.stat(CACHE_FILE).st_mtime > MAX_CACHE_AGE:
    ec2 = boto.connect_ec2()
    instances = ec2.get_only_instances()
    pickle.dump(instances, open(CACHE_FILE, 'w'), pickle.HIGHEST_PROTOCOL)
  
  return pickle.load(CACHE_FILE)


fb = Feedback()
instances = get_instances()

for instance in instances:
  match = 0
  query = sys.argv[1].split()
  text = ' '.join(parse_title(instance) + parse_subtitle(instance))

  for q in query:
    if q in text:
      match += 1
  if match == len(query):
    fb.add_item(
      title = ', '.join(parse_title(instance)),
      subtitle = ', '.join(parse_subtitle(instance)),
      arg = pick_result_field(instance)
    )

print fb
