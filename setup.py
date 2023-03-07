import setuptools


setuptools.setup(
    name="blueHat",
    version="0.0.1",
    author="Anthony Somtochukwu",
    author_email="somtochukwuanthony460@gmail.com",
    description=(" A Hacking Tool "
                "For all hackers."),
    url="https://github.com/anthony-devs/blue-hat/",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    packages=setuptools.find_packages(),
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "blueHat = BI6.cli:main",
        ]
    }
)
