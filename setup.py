from setuptools import find_packages, setup

setup(
    name="ai-governance-foundation",
    version="0.2.0",
    description="智能体工具调用权限登记与审计服务",
    package_dir={"": "src"},
    packages=find_packages("src"),
    python_requires=">=3.11",
)
