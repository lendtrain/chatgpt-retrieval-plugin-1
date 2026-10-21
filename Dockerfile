FROM python:3.10 AS trusted-python

# Refresh system trust too: pip and some application clients use this store.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY tests/security /tmp/security-tests
# Fail closed if the base distribution still trusts any incident chain.
RUN python /tmp/security-tests/check_emudhra_trust.py --system-only

# PSF's hash-pinned bootstrap protects the initial installer download.
# https://discuss.python.org/t/109576/5
RUN python -m pip --isolated --disable-pip-version-check install --no-cache-dir --no-deps \
    "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70" \
    && python -m pip --isolated --disable-pip-version-check install --no-cache-dir "certifi==2026.10.19" \
    && python /tmp/security-tests/check_emudhra_trust.py

FROM trusted-python AS requirements-stage

WORKDIR /tmp
ENV POETRY_VIRTUALENVS_CREATE=false
# Match the existing lock format and legacy secondary source setting.
RUN python -m pip --isolated --disable-pip-version-check install --no-cache-dir "poetry==1.4.2"
COPY ./pyproject.toml ./poetry.lock ./README.md /tmp/
RUN poetry check \
    && poetry export -f requirements.txt --output requirements.txt --without-hashes

FROM trusted-python

WORKDIR /code
COPY --from=requirements-stage /tmp/requirements.txt /code/requirements.txt
RUN python -m pip --isolated --disable-pip-version-check install --no-cache-dir --upgrade -r /code/requirements.txt \
    && python /tmp/security-tests/check_emudhra_trust.py

COPY . /code/

# Heroku uses PORT, Azure App Services uses WEBSITES_PORT, Fly.io uses 8080 by default
CMD ["sh", "-c", "uvicorn server.main:app --host 0.0.0.0 --port ${PORT:-${WEBSITES_PORT:-8080}}"]

