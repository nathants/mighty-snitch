import setuptools

setuptools.setup(
    version="0.0.1",
    name="snitch-prompt",
    install_requires=[
        'blessed',
    ],
    scripts=[
        'snitch-prompt',
        'color',
        'count-last',
    ],
    description='snitch-prompt',
)
