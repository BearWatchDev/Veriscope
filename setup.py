"""
Veriscope Setup Configuration
Lightweight malware analysis and detection rule generation tool
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="veriscope",
    version="1.3.0",
    author="BearWatchDev",
    author_email="BearWatchDev@pm.me",
    description="Unified IOC + ATT&CK + YARA + Sigma detection engine",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/BearWatchDev/Veriscope",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.8",
    install_requires=[
        # Core functionality uses only stdlib
        # Optional dependencies for API/GUI phases
    ],
    extras_require={
        "api": ["fastapi>=0.104.0", "uvicorn>=0.24.0"],
        "gui": ["flask>=3.0.0"],
        "all": ["fastapi>=0.104.0", "uvicorn>=0.24.0", "flask>=3.0.0"],
    },
    entry_points={
        "console_scripts": [
            "veriscope=veriscope.cli:main",
        ],
    },
)
