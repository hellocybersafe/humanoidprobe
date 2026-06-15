from setuptools import setup, find_packages
import os

version = {}
with open(os.path.join("humanoidprobe", "__version__.py")) as f:
    exec(f.read(), version)

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name             = "humanoidprobe",
    version          = version["__version__"],
    author           = "CyberSafeLabs",
    author_email     = "hello@cybersafelabs.com",
    description      = "WAF Intelligence Tool — Analyse WAF behaviour. Think like an attacker.",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url              = "https://github.com/cybersafelabs/humanoidprobe",
    packages         = find_packages(),
    package_data     = {"humanoidprobe": ["payloads/*.txt"]},
    install_requires = ["requests>=2.28.0"],
    python_requires  = ">=3.8",
    entry_points     = {
        "console_scripts": [
            "humanoidprobe=humanoidprobe.humanoidprobe:main",
        ],
    },
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
        "Environment :: Console",
    ],
    keywords = "security waf xss bugbounty penetration-testing cybersecurity",
)
