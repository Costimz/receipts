# The only thing model-written code ever runs in. Nothing is installed beyond the
# Python standard library and the read-only chain helper.
FROM python:3.12-slim
COPY chain.py /usr/local/lib/python3.12/site-packages/chain.py
RUN chmod -R a-w /usr/local/lib/python3.12/site-packages/chain.py
USER 65534:65534
WORKDIR /tmp
