import sys

from os import path
from setuptools import setup

if sys.version_info < (3,9):
    sys.exit("The current Python version is less than 3.9. Exiting.")
elif sys.version_info >= (3,13):
    sys.exit("The current Python version is greater than 3.12. Exiting.")

requirements_filepath = path.join(path.dirname(path.abspath(__file__)), "requirements.txt")
requirements = open(requirements_filepath).read().split()

setup(name='goosey',
      version='2.0.1',
      description='EntraID, Azure, M365, MDE Data Collector',
      author='Claire Casalnova, Jordan Eberst, Nicholas Kantor, Wellington Lee, Victoria Wallace',
      classifiers=[
          'Intended Audience :: Information Technology',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
          'Programming Language :: Python :: 3.11',
          'Programming Language :: Python :: 3.12',
      ],
      packages=['goosey'],
      python_requires='>=3.9',
      install_requires=requirements,
      zip_safe=False,
      include_package_data=True,
      entry_points={
          'console_scripts': ['goosey=goosey.main:main']
      }
    )
