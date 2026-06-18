from setuptools import setup, find_packages

setup(
    name="octopops",
    version="0.1",
    # Packages (core, discovery_scanners, processing_scanners, processors, helpers)
    packages=find_packages(),
    # octopops.py is a top-level module, not a package, so it must be declared
    # explicitly for the console_script entry point to resolve after install.
    py_modules=["octopops"],
    entry_points={
        "console_scripts": [
            "octopops=octopops:main",  # runs octopops.main()
        ],
    },
    install_requires=[
        "colorama",
    ],
    python_requires=">=3.8",
)
