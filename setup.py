from setuptools import setup, find_packages

with open("README.md") as readme_file:
    readme = readme_file.read()

with open('HISTORY.md') as history_file:
    history = history_file.read()

requirements = ["molten>=0.7.1", "Authlib>=0.10"]

test_requirements = ["pytest", "pytest-cov", "tox"]

setup(
    name="molten_jwt",
    version="0.1.1",
    description="A JSON Web Token component and middleware for the Molten web framework",
    long_description=readme + '\n\n' + history,
    long_description_content_type="text/markdown",
    author="Drew Bednar",
    author_email="drew@androiddrew.com",
    url="https://github.com/androiddrew/molten-jwt",
    packages=find_packages(include=["molten_jwt"]),
    include_package_data=True,
    install_requires=requirements,
    license="MIT",
    keywords="molten-jwt molten_jwt molten jwt JWT",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    extras_require={"testing": test_requirements},
)
