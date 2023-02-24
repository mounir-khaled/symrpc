import setuptools

setuptools.setup(
    name="angrcache",
    version='1.0.0',
    description='Angr Project Cache',
    author='Mounir Elgharabawy',
    packages=setuptools.find_packages(),
    requires=[
        "angr"
    ]
)