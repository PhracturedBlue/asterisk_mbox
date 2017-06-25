from setuptools import setup, find_packages
setup(
  name = 'asteriskvm',
  packages=find_packages(),
  version = '0.2.0',
  description = 'The client side of a client/server to interact with Asterisk voicemail mailboxes',
  long_description=open('README.rst').read(),
  author = 'PhracturedBlue',
  author_email = 'rc2012@pblue.org',
  url = 'https://github.com/PhracturedBlue/asteriskvm', # use the URL to the github repo
  keywords = ['testing', 'asterisk'], # arbitrary keywords
  classifiers = [],
)
