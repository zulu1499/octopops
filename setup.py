from setuptools import setup, find_packages

setup(
    name="octopops",
    version="0.1",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "octopops=orchestrator:main",  # runs orchestrator.main()
        ],
    },
    install_requires=[
        "colorama",
    ],
    python_requires=">=3.8",
)
