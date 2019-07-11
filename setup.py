from setuptools import setup

setup(
    name='csbootstrap',
    version='1.1.0',
    packages=['csbootstrap'],
    entry_points={
        'console_scripts': [
            'csbootstrap=csbootstrap.__main__:main'
        ]
    },
    install_requires=[
        'requests>=2.20.1',
        'pyOpenSSL>=18.0.0'
    ],
    python_requires='>=3, <4',
    url='https://github.com/deviceinsight/csbootstrap',
    license='Apache 2.0',
    author='Stephan Spindler',
    author_email='stephan.spindler@device-insight.com',
    description='A script for bootstrapping a device in CENTERSIGHT NG'
)
