#AWS Alfred Workflow
Currently only searches for ec2 instances.

##Usage:

  aws [profile<]query[>output_field]

Hit `Enter` to copy the output field to the clipboard.

For example:

    aws prod<prod-webserver>id
    
The a profile is not provided, it defaults to "default".

Out of the box, the output fields are:

* priv: private ip address
* pub: public ip address
* ami: image id (AMI)
* id: instance id

Default is "priv".

##Modifying
Three functions at the top of `aws.py` alter the input/output fields.
