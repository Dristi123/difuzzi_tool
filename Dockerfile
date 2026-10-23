# Difuzzi with both backends: Python (Atheris) and Java (Jazzer, JaCoCo, ASM, on a JDK 17).
#
#   docker build -t difuzzi .
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/work \
#       -e DIFUZZI_LLM_API_KEY -e DIFUZZI_LLM_MODEL \
#       difuzzi A.py B.py --examples ex.txt                                        # report in ./difuzzi-out
#
# On Apple Silicon, build and run with --platform linux/amd64 (Atheris ships Linux x86-64 wheels).
FROM python:3.12-slim-bookworm

# JDK 17 for the Java backend: javac compiles the programs and the harness. (Newer JDKs removed Thread.stop,
# which the harness uses to stop a candidate that runs past its time limit.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/difuzzi
COPY pyproject.toml README.md ./
COPY difuzzi ./difuzzi
RUN pip install --no-cache-dir .

# Jazzer, JaCoCo and ASM, fetched now so that runs need no network access (except to the LLM, if one is used)
ENV DIFUZZI_JAVA_DEPS=/opt/difuzzi/java-deps
RUN difuzzi-setup && chmod -R a+rX /opt/difuzzi

COPY examples ./examples

# Writable by any user (docker run --user ...): input generators and the compiled Java harness are cached here
ENV DIFUZZI_CACHE=/tmp/difuzzi-cache HOME=/tmp

# The LLM is configured at run time: -e DIFUZZI_LLM_API_KEY -e DIFUZZI_LLM_MODEL
WORKDIR /work
ENTRYPOINT ["difuzzi"]
CMD ["--help"]
