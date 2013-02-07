from distutils.core import setup

setup(
    name='Supermega',
    version='0.1.0',
    author='Lorenz Bauer',
    packages=['supermega', 'supermega.schemata'],
    # scripts=['bin/*.py'],
    # url='http://pypi.python.org/pypi/TowelStuff/',
    license='LICENSE.txt',
    description='The overengineered way to access the MEGA.co.nz service from Python.',
    long_description=open('README.md').read(),
    install_requires=[
        "requests >= 1.1.0",
        "pycrypto >= 2.6",
        "jsonschema >= 0.8.0"
    ],
)
