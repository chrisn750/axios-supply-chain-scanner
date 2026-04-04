"""
ghscan — GitHub Organization Security Scanner
"""

from setuptools import setup, find_packages

from ghscan import __version__

setup(
    name="ghscan",
    version=__version__,
    description="GitHub Organization Security Scanner with plugin architecture",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "requests",
    ],
    extras_require={
        "yaml": ["pyyaml"],
    },
    entry_points={
        "console_scripts": [
            "ghscan=ghscan.__main__:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
