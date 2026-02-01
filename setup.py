from setuptools import setup, find_packages
import re
from pathlib import Path

VERSIONFILE="awinrm/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

# Read README for long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

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
	license='MIT',
	description='Asynchronous Python library for Windows Remote Management',
	long_description=long_description,
	long_description_content_type='text/markdown',

	python_requires='>=3.8',
	classifiers=[
		"Programming Language :: Python :: 3.8",
		"Programming Language :: Python :: 3.9",
		"Programming Language :: Python :: 3.10",
		"Programming Language :: Python :: 3.11",
		"Programming Language :: Python :: 3.12",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	],
	install_requires=[
		'unicrypto>=0.0.11',
		'httpx>=0.25.0',
		'asyauth>=0.0.14',
		'aioconsole>=0.8.1',
		'xmltodict',
	],

    entry_points={
		'console_scripts': [
			'awinrm-runcmd = awinrm.examples.runcmd:main',
			'awinrm-cmdshell = awinrm.examples.shell:main',
			'awinrm-authcheck = awinrm.examples.authcheck:main',
		],
	}
)
