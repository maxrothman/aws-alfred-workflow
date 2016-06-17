#AWS Alfred Workflow
Search for EC2 instances

Supports multiple accounts, mutifactor authentication, and cross-account "assume_role" authentication

##Usage:

This workflow contains several entry points:

###aws
The main entry point for the workflow. It will prompt you to select a profile, prompt you for an MFA token if necessary, and give you a list of instances to filter.

By default, when selecting an instance, its private IP address is copied to the clipboard. By holding shift, you will be prompted to select a different output field.

You can find details about configuring profiles in the [Boto documentation](http://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration).

###lastaws
Skips the profile selection and uses the last selected profile. The rest of the workflow acts as described above.

###outputaws
Re-opens the output field selection list using the last-selected instance. This can be used to add multiple attributes about an instance to the clipboard.


##Modifying
You can modify the default output field and the instance attributes in the title/subtitle of the instance list by modifying config values at the top of `aws.py`.
