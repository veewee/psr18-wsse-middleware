# Verification runtime for php-soap/psr18-wsse-middleware.
#
# This package requires PHP ~8.4.21 || ~8.5.0, because a php-src ext/dom defect below 8.4.21 corrupts the
# canonical form of a tree that has had a namespace declaration added to it. Most hosts sit below that floor,
# so phpunit, psalm and mago cannot run there. Build this image instead.
#
#   docker build -t wsse-verify:8.4 -f .agents/skills/verify-suggestion-with-spec/references/Dockerfile .
#   docker run --rm -v "$PWD":/app -w /app wsse-verify:8.4 ./vendor/bin/phpunit --fail-on-skipped
#
# The extension set mirrors the one .github/workflows/tests.yaml installs. ext-gmp and ext-bcmath are optional
# for the package but included here: phpseclib does the RSA and ECDSA big-integer math in userland and is far
# slower without them, and the CI test job installs both.
FROM php:8.4-cli

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libicu-dev libgmp-dev libxml2-dev libzip-dev git unzip \
    && docker-php-ext-install -j"$(nproc)" intl gmp bcmath soap zip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app
