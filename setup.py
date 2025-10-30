from setuptools import setup, find_packages

setup(
    name="kali-master-cli",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "rich",
        "prompt-toolkit",
        "fuzzywuzzy",
        "pyperclip",
        "python-Levenshtein"  # accélère fuzzy
    ],
    entry_points={"console_scripts": ["kali-master=kali_master.core:interactive_cli"]},
    package_data={"kali_master": ["data/*.json"]},
)
