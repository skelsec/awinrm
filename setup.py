from setuptools import setup, find_packages
import re

VERSIONFILE="awinrm/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

setup(
	# Application name:
	name="awinrm",

	# Version number (initial):
	version=verstr,

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsecprojects.com",

	# Packages
	packages=find_packages(exclude=["tests*"]),

	# Include additional files into the package
	include_package_data=True,

	# Details
	url="https://github.com/skelsec/awinrm",

	zip_safe = False,
	#license='MIT license',
	description='Asynchronous Python library for Windows Remote Management',
	long_description='Asynchronous Python library for Windows Remote Management',

	python_requires='>=3.7',
	classifiers=[
		"Programming Language :: Python :: 3.7",
		"Programming Language :: Python :: 3.8",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	],
	install_requires=[
		'unicrypto==0.0.10',
		'asysocks>=0.2.10',
        'asyauth>=0.0.14',
		'six',
        'xmltodict',
	],

    entry_points={
		'console_scripts': [
			'awinrm-runcmd = awinrm.examples.runcmd:main',
            'awinrm-cmdshell = awinrm.examples.shell:main',
		],
	}
)