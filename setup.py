from setuptools import setup, find_packages

setup(
    name="soc-sentinel",
    version="1.0.0",
    description="SOC Log Monitoring and Threat Detection Platform (SIEM-Lite)",
    author="Security Operations Team",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "streamlit>=1.35.0",
        "pandas>=2.2.0",
        "plotly>=5.22.0",
        "pytest>=8.2.0",
    ],
)
