import sys
if sys.version_info < (3,7):
    sys.exit("The current Python version is less than 3.7. Exiting.")
elif sys.version_info >= (3,11):
    sys.exit("The current Python version is greater than 3.10. Exiting.")

from setuptools import setup
setup(name='goosey',
      version='1.1.1',
      description='AzureAD, Azure and M365 Data Collector',
      author='Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace',
      classifiers=[
          'Intended Audience :: Information Technology',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
      ],
      packages=['goosey'],
      python_requires='>=3.7,<=3.10.10',
      install_requires=[
          'cryptography>=36.0.1,<39',
          'requests',
          'webdrivermanager',
          'aiohttp==3.8.1',
          'async-timeout==4.0.2',
          'openpyxl',
          'azure-mgmt-web',
          'azure-mgmt-storage',
          'darkdetect',
          'azure-mgmt-network',
          'colored',
          'azure-mgmt-resource',
          'azure-mgmt-monitor',
          'azure-identity',
          'azure-mgmt-compute',
          'azure-storage-blob',
          'azure-mgmt-security',
          'selenium',
          'selenium-wire',
          'adal>=1.2.7',
          'msrestazure',
          'Gooey==1.0.8.1',
          'typing-extensions>=4.1.1',
          'pyAesCrypt'       
      ],
      zip_safe=False,
      include_package_data=True,
      entry_points={
          'console_scripts': ['goosey=goosey.main:main',
                              'goosey-gui=goosey.guimain:main']
      }
    )
