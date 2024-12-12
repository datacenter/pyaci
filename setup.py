from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pyaci',

    version='1.0.0',

    description='Python Bindings for Cisco ACI REST API',
    long_description=long_description,

    url='https://github.com/datacenter/pyaci',

    author='Praveen Kumar',
    author_email='praveek6@cisco.com',

    license='Apache',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',
        'Topic :: System :: Networking',

        'License :: OSI Approved :: Apache Software License',

        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],

    keywords='cisco aci apic datacenter sdn',

    packages=find_packages(exclude=['docs', 'examples', 'tests']),

    # Install files from MANIFEST.in.
    include_package_data=True,

    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=[
        'Flask<=3.0.3',
        'lxml',
        'paramiko',
        'parse',
        'pyopenssl==22.0.0',
        'cryptography==38.0.4',
        'pyyaml',
        'requests',
        'scp',
        'websocket-client',
        'xmltodict',
        'six'
    ],

    # List additional groups of dependencies here (e.g. development
    # dependencies). You can install these using the following syntax,
    # for example:
    # $ pip install -e .[dev,test]
    extras_require={
        'doc': [
            'sphinx',
        ],

        'test': [
            'coverage',
            'httpretty',
            'nose',
            'sure',
        ],
    },

    scripts=[
        'scripts/metagen.py',
        'scripts/rmetagen.py',
        'scripts/xml2pyaci',
    ]
)
