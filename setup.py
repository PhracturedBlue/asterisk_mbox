from setuptools import setup, find_packages
setup(
  name = 'asteriskvm',
  packages=find_packages(),
  version = '0.1.6',
  description = 'A client/server to interact with Asterisk voicemail mailboxes',
  long_description=open('README.rst').read(),
  author = 'PhracturedBlue',
  author_email = 'rc2012@pblue.org',
  url = 'https://github.com/PhracturedBlue/asteriskvm', # use the URL to the github repo
  keywords = ['testing', 'asterisk'], # arbitrary keywords
  classifiers = [],
  install_requires=[
        "inotify",
        "SpeechRecognition",
   ],
   entry_points = {
        'console_scripts': [
            'asteriskvm-server = asteriskvm.server:main'
        ]
   },

)
