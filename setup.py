import setuptools


setuptools.setup(
    name="bi6",
    version="0.0.1",
    author="Anthony Somtochukwu",
    author_email="somtochukwuanthony460@gmail.com",
    description=(" A Hacking Tool "
                "For all hackers."),
    url="https://github.com/anthony-devs/bi6/",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    packages=setuptools.find_packages(),
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "bi6 = BI6.cli:main",
        ]
    }
)